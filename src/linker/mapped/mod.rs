use super::layout::{LayoutAddress, LayoutSectionId, MemoryLayoutPlan};
use crate::linker::plan::{LinkModuleId, LinkPlan};
use crate::{
    Result,
    elf::{ElfDyn, ElfDynamicTag, ElfPhdr, ElfPhdrs, ElfProgramType, ElfRelType, ElfSymbol},
    image::{LoadedMemorySlice, RawDylib, ScannedDylib, ScannedRelocationAddend, ScannedSectionId},
    loader::DynLifecycleHandler,
    segment::ElfSegments,
    tls::{TlsInfo, TlsResolver},
    try_cast_slice, try_cast_slice_mut,
};
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::ptr::NonNull;
use elf::abi::{SHN_ABS, SHN_UNDEF};

mod arena;

pub(crate) use arena::{
    MappedArenaMap, map_planned_section_arenas, populate_mapped_arenas, protect_mapped_arenas,
};

struct RuntimeModuleMemory {
    module_id: LinkModuleId,
    base: usize,
    segments: ElfSegments,
    memory_slices: Box<[LoadedMemorySlice]>,
}

impl RuntimeModuleMemory {
    fn section_module_offset(
        &self,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
        section: LayoutSectionId,
    ) -> Option<usize> {
        let placement = layout.section_placement(section)?;
        mapped_section_arenas
            .address(placement.address())
            .and_then(|actual_address| actual_address.checked_sub(self.base))
    }

    fn remap_source_address_in_section(
        &self,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
        section: LayoutSectionId,
        source_address: usize,
    ) -> Option<usize> {
        let metadata = layout.section_metadata(section);
        let module_offset = self.section_module_offset(layout, mapped_section_arenas, section)?;
        if metadata.size() == 0 && source_address == metadata.source_address() {
            return Some(module_offset);
        }

        let delta = source_address.checked_sub(metadata.source_address())?;
        (delta < metadata.size()).then_some(module_offset + delta)
    }

    fn remap_source_address(
        &self,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
        source_address: usize,
    ) -> Option<usize> {
        layout
            .module(self.module_id)
            .alloc_sections()
            .iter()
            .copied()
            .find_map(|section| {
                self.remap_source_address_in_section(
                    layout,
                    mapped_section_arenas,
                    section,
                    source_address,
                )
            })
    }

    fn remap_symbol_value(
        &self,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
        section_index: usize,
        value: usize,
    ) -> Option<usize> {
        if section_index == SHN_UNDEF as usize || section_index == SHN_ABS as usize {
            return Some(value);
        }

        let section =
            layout.module_section_id(self.module_id, ScannedSectionId::new(section_index))?;
        self.remap_source_address_in_section(layout, mapped_section_arenas, section, value)
            .or_else(|| {
                let metadata = layout.section_metadata(section);
                let module_offset =
                    self.section_module_offset(layout, mapped_section_arenas, section)?;
                (value < metadata.size()).then_some(module_offset + value)
            })
    }

    fn remap_runtime_relocation_offset(
        &self,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
        target: Option<LayoutSectionId>,
        original_offset: usize,
    ) -> Option<usize> {
        target
            .and_then(|section| {
                self.remap_source_address_in_section(
                    layout,
                    mapped_section_arenas,
                    section,
                    original_offset,
                )
                .or_else(|| {
                    let metadata = layout.section_metadata(section);
                    let module_offset =
                        self.section_module_offset(layout, mapped_section_arenas, section)?;
                    (original_offset < metadata.size()).then_some(module_offset + original_offset)
                })
            })
            .or_else(|| self.remap_source_address(layout, mapped_section_arenas, original_offset))
    }

    fn section_offset_for_source_address(
        &self,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
        source_address: usize,
    ) -> Option<(LayoutSectionId, usize)> {
        layout
            .module(self.module_id)
            .alloc_sections()
            .iter()
            .copied()
            .find_map(|section| {
                self.section_module_offset(layout, mapped_section_arenas, section)?;
                let metadata = layout.section_metadata(section);
                if metadata.size() == 0 {
                    return None;
                }
                let offset = source_address.checked_sub(metadata.source_address())?;
                (offset < metadata.size()).then_some((section, offset))
            })
    }

    fn section_offset_for_layout_address(
        &self,
        layout: &MemoryLayoutPlan,
        address: LayoutAddress,
    ) -> Option<(LayoutSectionId, usize)> {
        layout
            .module(self.module_id)
            .alloc_sections()
            .iter()
            .copied()
            .find_map(|section| {
                let metadata = layout.section_metadata(section);
                let placement = layout.section_placement(section)?;
                if metadata.size() == 0 || placement.arena() != address.arena() {
                    return None;
                }
                let offset = address.offset().checked_sub(placement.offset())?;
                (offset < metadata.size()).then_some((section, offset))
            })
    }
}

struct RuntimeMetadataRewriter<'a, K, D: 'static> {
    module_id: LinkModuleId,
    plan: &'a mut LinkPlan<K, D>,
    runtime: &'a RuntimeModuleMemory,
    mapped_section_arenas: &'a MappedArenaMap,
}

impl<'a, K, D> RuntimeMetadataRewriter<'a, K, D>
where
    K: Clone + Ord,
    D: 'static,
{
    fn new(
        module_id: LinkModuleId,
        plan: &'a mut LinkPlan<K, D>,
        runtime: &'a RuntimeModuleMemory,
        mapped_section_arenas: &'a MappedArenaMap,
    ) -> Self {
        Self {
            module_id,
            plan,
            runtime,
            mapped_section_arenas,
        }
    }

    fn rewrite(&mut self) -> Result<()> {
        self.apply_retained_relocations()?;
        self.rewrite_symbol_tables()?;
        self.rewrite_allocated_relocation_sections()?;
        self.rewrite_dynamic_section()?;
        Ok(())
    }

    fn apply_retained_relocations(&mut self) -> Result<()> {
        let relocation_sections = self
            .plan
            .memory_layout()
            .module(self.module_id)
            .relocation_sections()
            .to_vec();

        for relocation_section in relocation_sections {
            let Some(symbol_table_section) = self
                .plan
                .memory_layout()
                .section_metadata(relocation_section)
                .linked_section()
            else {
                continue;
            };

            let _ = self.plan.section_data(symbol_table_section)?;
            let rewrites = {
                let (data, layout) = self.plan.section_data_with_layout(relocation_section)?;
                let target_section = layout.section_metadata(relocation_section).info_section();
                let entries = data.try_cast_slice::<ElfRelType>().ok_or_else(|| {
                    crate::custom_error(
                        "retained relocation section bytes do not match relocation entries",
                    )
                })?;
                let symbols = layout
                    .sections()
                    .data(symbol_table_section)
                    .ok_or_else(|| {
                        crate::custom_error("retained relocation symbol table was not materialized")
                    })?
                    .try_cast_slice::<ElfSymbol>()
                    .ok_or_else(|| {
                        crate::custom_error(
                            "retained relocation symbol table bytes do not match symbol entries",
                        )
                    })?;

                let mut rewrites = Vec::new();
                for entry in entries {
                    let Some(address) = resolve_relocation_site_address(
                        layout,
                        self.module_id,
                        target_section,
                        entry.r_offset(),
                    ) else {
                        continue;
                    };
                    let Some(actual_site) = self.mapped_section_arenas.address(address) else {
                        continue;
                    };
                    let Some((section_id, section_offset)) = self
                        .runtime
                        .section_offset_for_layout_address(layout, address)
                    else {
                        continue;
                    };
                    let Some(symbol) = symbols.get(entry.r_symbol()) else {
                        continue;
                    };
                    let symbol_value = self
                        .runtime
                        .remap_symbol_value(
                            layout,
                            self.mapped_section_arenas,
                            symbol.st_shndx(),
                            symbol.st_value(),
                        )
                        .unwrap_or_else(|| symbol.st_value());
                    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
                    let addend = ScannedRelocationAddend::Implicit;
                    #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
                    let addend = ScannedRelocationAddend::Explicit(entry.r_addend(0));
                    let value = rewrite_relocation_value(
                        entry.r_type(),
                        symbol_value,
                        addend,
                        actual_site - self.runtime.base,
                    )?;
                    rewrites.push((section_id, section_offset, value));
                }
                rewrites
            };

            for (section_id, section_offset, value) in rewrites {
                let data = self.plan.section_data_mut(section_id)?;
                write_relocation_value(data.as_bytes_mut(), section_offset, value)?;
            }
        }

        Ok(())
    }

    fn rewrite_symbol_tables(&mut self) -> Result<()> {
        let sections = self
            .plan
            .memory_layout()
            .module(self.module_id)
            .symbol_table_sections()
            .to_vec();
        for section in sections {
            let rewrites = {
                let (data, layout) = self.plan.section_data_with_layout(section)?;
                data.try_cast_slice::<ElfSymbol>()
                    .ok_or_else(|| {
                        crate::custom_error("section bytes do not match the requested type layout")
                    })?
                    .iter()
                    .enumerate()
                    .filter_map(|(index, symbol)| {
                        self.runtime
                            .remap_symbol_value(
                                layout,
                                self.mapped_section_arenas,
                                symbol.st_shndx(),
                                symbol.st_value(),
                            )
                            .map(|value| (index, value))
                    })
                    .collect::<Vec<_>>()
            };
            if rewrites.is_empty() {
                continue;
            }

            let data = self.plan.section_data_mut(section)?;
            let symbols = data.try_cast_slice_mut::<ElfSymbol>().ok_or_else(|| {
                crate::custom_error("section bytes do not match the requested type layout")
            })?;
            for (index, value) in rewrites {
                if let Some(symbol) = symbols.get_mut(index) {
                    symbol.set_value(value);
                }
            }
        }

        Ok(())
    }

    fn rewrite_allocated_relocation_sections(&mut self) -> Result<()> {
        let sections = self
            .plan
            .memory_layout()
            .module(self.module_id)
            .allocated_relocation_sections()
            .to_vec();
        for section in sections {
            if self
                .runtime
                .section_module_offset(
                    self.plan.memory_layout(),
                    self.mapped_section_arenas,
                    section,
                )
                .is_none()
            {
                continue;
            }
            let Some(relocation) = self
                .plan
                .memory_layout()
                .section_metadata(section)
                .info_section()
            else {
                return Err(crate::custom_error(
                    "retained relocation section is missing relocation metadata",
                ));
            };

            let rewrites = {
                let (data, layout) = self.plan.section_data_with_layout(section)?;
                data.try_cast_slice::<ElfRelType>()
                    .ok_or_else(|| {
                        crate::custom_error("section bytes do not match the requested type layout")
                    })?
                    .iter()
                    .enumerate()
                    .filter_map(|(index, rel)| {
                        self.runtime
                            .remap_runtime_relocation_offset(
                                layout,
                                self.mapped_section_arenas,
                                Some(relocation),
                                rel.r_offset(),
                            )
                            .map(|offset| (index, offset))
                    })
                    .collect::<Vec<_>>()
            };
            if rewrites.is_empty() {
                continue;
            }

            let data = self.plan.section_data_mut(section)?;
            let rels = data.try_cast_slice_mut::<ElfRelType>().ok_or_else(|| {
                crate::custom_error("section bytes do not match the requested type layout")
            })?;
            for (index, offset) in rewrites {
                if let Some(rel) = rels.get_mut(index) {
                    rel.set_offset(offset);
                }
            }
        }

        Ok(())
    }

    fn rewrite_dynamic_section(&mut self) -> Result<()> {
        let (dynamic_address, dynamic_size) = dynamic_range(self.module_id, self.plan)?;
        let (section_id, section_offset) = self
            .runtime
            .section_offset_for_source_address(
                self.plan.memory_layout(),
                self.mapped_section_arenas,
                dynamic_address,
            )
            .ok_or_else(|| {
                crate::custom_error("failed to remap PT_DYNAMIC into arena-backed memory")
            })?;
        let end = section_offset
            .checked_add(dynamic_size)
            .ok_or_else(|| crate::custom_error("arena-backed PT_DYNAMIC range overflowed"))?;

        let rewrites = {
            let (data, layout) = self.plan.section_data_with_layout(section_id)?;
            let dyns =
                try_cast_slice::<ElfDyn>(data.as_ref().get(section_offset..end).ok_or_else(
                    || crate::custom_error("arena-backed PT_DYNAMIC range exceeds section data"),
                )?)
                .ok_or_else(|| {
                    crate::custom_error("section bytes do not match the requested type layout")
                })?;
            let mut rewrites = Vec::new();
            for (index, dyn_) in dyns.iter().enumerate() {
                let tag = dyn_.tag();
                if let Some(value) = remap_dynamic_value(
                    self.runtime,
                    layout,
                    self.mapped_section_arenas,
                    tag,
                    dyn_.value(),
                ) {
                    rewrites.push((index, value));
                }
                if tag == ElfDynamicTag::NULL {
                    break;
                }
            }
            rewrites
        };
        if rewrites.is_empty() {
            return Ok(());
        }

        let data = self.plan.section_data_mut(section_id)?;
        let dyns = try_cast_slice_mut::<ElfDyn>(
            data.as_bytes_mut()
                .get_mut(section_offset..end)
                .ok_or_else(|| {
                    crate::custom_error("arena-backed PT_DYNAMIC range exceeds section data")
                })?,
        )
        .ok_or_else(|| {
            crate::custom_error("section bytes do not match the requested type layout")
        })?;
        for (index, value) in rewrites {
            if let Some(dyn_) = dyns.get_mut(index) {
                dyn_.set_value(value);
            }
        }
        Ok(())
    }
}

pub(crate) fn repair_arena_layout_module<K, D>(
    module_id: LinkModuleId,
    plan: &mut LinkPlan<K, D>,
    mapped_section_arenas: &MappedArenaMap,
) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let runtime = build_runtime_memory(module_id, plan.memory_layout(), mapped_section_arenas)?;
    let mut rewriter =
        RuntimeMetadataRewriter::new(module_id, plan, &runtime, mapped_section_arenas);
    rewriter.rewrite()
}

fn dynamic_range<K, D>(module_id: LinkModuleId, plan: &LinkPlan<K, D>) -> Result<(usize, usize)>
where
    K: Clone + Ord,
    D: 'static,
{
    let scanned = plan
        .scanned_module(module_id)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing scan metadata"))?;
    let dynamic = program_header(scanned.phdrs(), ElfProgramType::DYNAMIC)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
    Ok((dynamic.p_vaddr(), dynamic.p_memsz()))
}

pub(crate) fn build_arena_raw_dylib<D, Tls>(
    module_id: LinkModuleId,
    mut scanned: ScannedDylib<D>,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
    init_fn: DynLifecycleHandler,
    fini_fn: DynLifecycleHandler,
    force_static_tls: bool,
) -> Result<RawDylib<D>>
where
    D: Default + 'static,
    Tls: TlsResolver,
{
    let runtime = build_runtime_memory(module_id, layout, mapped_section_arenas)?;

    let original_phdrs = scanned.phdrs().to_vec();
    let dynamic_ptr = dynamic_ptr(&original_phdrs, &runtime, layout, mapped_section_arenas)?;
    let eh_frame_hdr = eh_frame_hdr(&original_phdrs, &runtime, layout, mapped_section_arenas);
    let tls_info = tls_info(&original_phdrs, &runtime, layout, mapped_section_arenas);
    let entry = remap_entry(
        scanned.ehdr().e_entry(),
        &runtime,
        layout,
        mapped_section_arenas,
    );
    let name = scanned.name().to_string();
    let user_data = core::mem::take(scanned.user_data_mut());

    RawDylib::from_parts::<Tls>(crate::image::DynamicImageParts {
        name,
        entry,
        interp: None,
        phdrs: ElfPhdrs::Vec(original_phdrs),
        dynamic_ptr,
        eh_frame_hdr,
        tls_info,
        force_static_tls,
        relro: None,
        segments: runtime.segments,
        memory_slices: runtime.memory_slices,
        init_fn,
        fini_fn,
        user_data,
    })
}

fn build_runtime_memory(
    module_id: LinkModuleId,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
) -> Result<RuntimeModuleMemory> {
    let module = layout.module(module_id);

    let mut placed_sections = Vec::with_capacity(module.alloc_sections().len());
    for section_id in module.alloc_sections().iter().copied() {
        let Some(placement) = layout.section_placement(section_id) else {
            continue;
        };
        let metadata = layout.section_metadata(section_id);
        let arena = mapped_section_arenas
            .get(placement.arena())
            .ok_or_else(|| {
                crate::custom_error("arena-backed module referenced an unmapped arena")
            })?;
        let actual_address = arena
            .address(placement.offset())
            .ok_or_else(|| crate::custom_error("arena-backed module section address overflowed"))?;
        placed_sections.push((placement, actual_address, metadata.size()));
    }

    let Some(base) = placed_sections
        .iter()
        .map(|(_, actual_address, _)| *actual_address)
        .min()
    else {
        return Err(crate::custom_error(
            "arena-backed module does not own any alloc sections",
        ));
    };

    let mut segment_slices = Vec::with_capacity(placed_sections.len());
    let mut memory_slices = placed_sections
        .iter()
        .map(|(_, actual_address, size)| LoadedMemorySlice::new(*actual_address, *size))
        .collect::<Vec<_>>();
    memory_slices.sort_unstable_by_key(|slice| slice.base());

    for (placement, actual_address, size) in &placed_sections {
        let arena = mapped_section_arenas
            .get(placement.arena())
            .ok_or_else(|| {
                crate::custom_error("arena-backed module referenced an unmapped arena")
            })?;
        segment_slices.push(ElfSegments::slice(
            actual_address - base,
            *size,
            arena.backing(),
        ));
    }

    Ok(RuntimeModuleMemory {
        module_id,
        base,
        segments: ElfSegments::from_slices(base, segment_slices),
        memory_slices: memory_slices.into_boxed_slice(),
    })
}

fn resolve_relocation_site_address(
    layout: &MemoryLayoutPlan,
    module_id: LinkModuleId,
    target_section: Option<LayoutSectionId>,
    source_address: usize,
) -> Option<LayoutAddress> {
    if let Some(section_id) = target_section {
        return resolve_relocation_site_address_in_section(layout, section_id, source_address);
    }

    layout
        .module(module_id)
        .alloc_sections()
        .iter()
        .copied()
        .find_map(|section_id| {
            resolve_relocation_site_address_in_section(layout, section_id, source_address)
        })
}

fn resolve_relocation_site_address_in_section(
    layout: &MemoryLayoutPlan,
    section_id: LayoutSectionId,
    source_address: usize,
) -> Option<LayoutAddress> {
    let placement = layout.section_placement(section_id)?;
    let metadata = layout.section_metadata(section_id);
    let delta = source_address.checked_sub(metadata.source_address())?;
    (delta < metadata.size())
        .then(|| LayoutAddress::new(placement.arena(), placement.offset() + delta))
}

fn dynamic_ptr(
    phdrs: &[ElfPhdr],
    runtime: &RuntimeModuleMemory,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
) -> Result<NonNull<ElfDyn>> {
    let phdr = program_header(phdrs, ElfProgramType::DYNAMIC)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
    let offset = runtime
        .remap_source_address(layout, mapped_section_arenas, phdr.p_vaddr())
        .ok_or_else(|| crate::custom_error("failed to remap PT_DYNAMIC"))?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
        .ok_or_else(|| crate::custom_error("PT_DYNAMIC remapped to a null pointer"))
}

fn eh_frame_hdr(
    phdrs: &[ElfPhdr],
    runtime: &RuntimeModuleMemory,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
) -> Option<NonNull<u8>> {
    let phdr = program_header(phdrs, ElfProgramType::GNU_EH_FRAME)?;
    let offset = runtime.remap_source_address(layout, mapped_section_arenas, phdr.p_vaddr())?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
}

fn tls_info(
    phdrs: &[ElfPhdr],
    runtime: &RuntimeModuleMemory,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
) -> Option<TlsInfo> {
    let phdr = program_header(phdrs, ElfProgramType::TLS)?;
    let offset = runtime.remap_source_address(layout, mapped_section_arenas, phdr.p_vaddr())?;
    let image = runtime.segments.get_slice::<u8>(offset, phdr.p_filesz());
    Some(TlsInfo::new(phdr, image))
}

fn remap_entry(
    original_entry: usize,
    runtime: &RuntimeModuleMemory,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
) -> crate::relocation::RelocAddr {
    runtime
        .remap_source_address(layout, mapped_section_arenas, original_entry)
        .map(|offset| runtime.segments.base_addr().offset(offset))
        .unwrap_or_else(|| runtime.segments.base_addr().offset(original_entry))
}

fn program_header(phdrs: &[ElfPhdr], kind: ElfProgramType) -> Option<&ElfPhdr> {
    phdrs.iter().find(|phdr| phdr.program_type() == kind)
}

fn remap_dynamic_value(
    runtime: &RuntimeModuleMemory,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &MappedArenaMap,
    tag: ElfDynamicTag,
    value: usize,
) -> Option<usize> {
    match tag {
        ElfDynamicTag::PLTGOT
        | ElfDynamicTag::HASH
        | ElfDynamicTag::GNU_HASH
        | ElfDynamicTag::STRTAB
        | ElfDynamicTag::SYMTAB
        | ElfDynamicTag::JMPREL
        | ElfDynamicTag::RELR
        | ElfDynamicTag::RELA
        | ElfDynamicTag::REL
        | ElfDynamicTag::INIT
        | ElfDynamicTag::FINI
        | ElfDynamicTag::INIT_ARRAY
        | ElfDynamicTag::FINI_ARRAY
        | ElfDynamicTag::VERSYM
        | ElfDynamicTag::VERNEED
        | ElfDynamicTag::VERDEF => {
            runtime.remap_source_address(layout, mapped_section_arenas, value)
        }
        _ => None,
    }
}

fn rewrite_relocation_value(
    relocation_type: usize,
    symbol_value: usize,
    addend: crate::image::ScannedRelocationAddend,
    new_place: usize,
) -> Result<RewrittenRelocationValue> {
    #[cfg(target_arch = "x86_64")]
    {
        let addend = match addend {
            crate::image::ScannedRelocationAddend::Explicit(addend) => addend,
            crate::image::ScannedRelocationAddend::Implicit => {
                return Err(crate::custom_error(
                    "implicit retained relocation addends are not supported on x86_64",
                ));
            }
        };
        let symbol_value = symbol_value as i128;
        let addend = addend as i128;
        let new_place = new_place as i128;

        let value = match relocation_type as u32 {
            elf::abi::R_X86_64_NONE => return Ok(RewrittenRelocationValue::Skip),
            elf::abi::R_X86_64_64 => {
                RewrittenRelocationValue::U64((symbol_value + addend) as usize)
            }
            elf::abi::R_X86_64_32 => RewrittenRelocationValue::U32(
                u32::try_from(symbol_value + addend).map_err(|_| {
                    crate::custom_error(
                        "retained relocation overflowed while rewriting R_X86_64_32",
                    )
                })?,
            ),
            elf::abi::R_X86_64_32S => RewrittenRelocationValue::I32(
                i32::try_from(symbol_value + addend).map_err(|_| {
                    crate::custom_error(
                        "retained relocation overflowed while rewriting R_X86_64_32S",
                    )
                })?,
            ),
            elf::abi::R_X86_64_PC32 | elf::abi::R_X86_64_PLT32 | elf::abi::R_X86_64_GOTPCREL => {
                let new = symbol_value + addend - new_place;
                RewrittenRelocationValue::I32(i32::try_from(new).map_err(|_| {
                    crate::custom_error(
                        "retained relocation overflowed while rewriting x86_64 PC-relative relocation",
                    )
                })?)
            }
            _ => {
                return Err(crate::custom_error(
                    "unsupported retained relocation type for x86_64 arena repair",
                ));
            }
        };

        Ok(value)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (relocation_type, symbol_value, addend, new_place);
        Err(crate::custom_error(
            "arena-backed retained relocation repair is not implemented for this architecture",
        ))
    }
}

enum RewrittenRelocationValue {
    Skip,
    U64(usize),
    U32(u32),
    I32(i32),
}

fn write_relocation_value(
    section_bytes: &mut [u8],
    section_offset: usize,
    value: RewrittenRelocationValue,
) -> Result<()> {
    match value {
        RewrittenRelocationValue::Skip => {}
        RewrittenRelocationValue::U64(value) => {
            write_relocation_bytes(section_bytes, section_offset, &value.to_ne_bytes())?;
        }
        RewrittenRelocationValue::U32(value) => {
            write_relocation_bytes(section_bytes, section_offset, &value.to_ne_bytes())?;
        }
        RewrittenRelocationValue::I32(value) => {
            write_relocation_bytes(section_bytes, section_offset, &value.to_ne_bytes())?;
        }
    }
    Ok(())
}

fn write_relocation_bytes(section_bytes: &mut [u8], offset: usize, src: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(src.len())
        .ok_or_else(|| crate::custom_error("retained relocation write range overflowed"))?;
    let dst = section_bytes
        .get_mut(offset..end)
        .ok_or_else(|| crate::custom_error("retained relocation write range exceeds section"))?;
    dst.copy_from_slice(src);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        elf::{ElfSectionFlags, ElfSectionType},
        linker::layout::{
            LayoutArena, LayoutArenaId, LayoutArenaSharing, LayoutMemoryClass,
            LayoutSectionMetadata, ModuleLayout, SectionPlacement,
        },
    };

    const ROOT_MODULE: LinkModuleId = LinkModuleId::new(0);

    fn section_flags(class: LayoutMemoryClass) -> ElfSectionFlags {
        let mut flags = ElfSectionFlags::ALLOC;
        match class {
            LayoutMemoryClass::Code => flags |= ElfSectionFlags::EXECINSTR,
            LayoutMemoryClass::WritableData | LayoutMemoryClass::ThreadLocalData => {
                flags |= ElfSectionFlags::WRITE;
            }
            LayoutMemoryClass::ReadOnlyData => {}
        }
        if class == LayoutMemoryClass::ThreadLocalData {
            flags |= ElfSectionFlags::TLS;
        }
        flags
    }

    fn alloc_section_with_address(
        layout: &mut MemoryLayoutPlan,
        scanned_section: usize,
        name: &str,
        class: LayoutMemoryClass,
        source_address: usize,
    ) -> LayoutSectionId {
        layout.sections_mut().insert(
            ROOT_MODULE,
            LayoutSectionMetadata::new(
                scanned_section,
                name,
                ElfSectionType::PROGBITS,
                section_flags(class),
                None::<LayoutSectionId>,
                None::<LayoutSectionId>,
                source_address,
                0,
                64,
                16,
            ),
        )
    }

    fn relocation_section(
        layout: &mut MemoryLayoutPlan,
        scanned_section: usize,
        target: Option<LayoutSectionId>,
    ) -> LayoutSectionId {
        layout.sections_mut().insert(
            ROOT_MODULE,
            LayoutSectionMetadata::new(
                scanned_section,
                ".rela.text",
                ElfSectionType::RELA,
                ElfSectionFlags::empty(),
                None::<LayoutSectionId>,
                target,
                0,
                0,
                24,
                8,
            ),
        )
    }

    #[test]
    fn relocation_site_address_respects_sh_info_target() {
        let mut layout = MemoryLayoutPlan::default();
        let text =
            alloc_section_with_address(&mut layout, 5, ".text", LayoutMemoryClass::Code, 0x1000);
        let data = alloc_section_with_address(
            &mut layout,
            6,
            ".data",
            LayoutMemoryClass::WritableData,
            0x2000,
        );
        let reloc = relocation_section(&mut layout, 9, Some(text));
        let module =
            ModuleLayout::from_sections([(5, text), (6, data), (9, reloc)], layout.sections());
        layout.insert_module(ROOT_MODULE, module);
        layout.create_arena(LayoutArena::new(
            4096,
            LayoutMemoryClass::Code,
            LayoutArenaSharing::Shared,
        ));
        layout.create_arena(LayoutArena::new(
            4096,
            LayoutMemoryClass::WritableData,
            LayoutArenaSharing::Private,
        ));
        layout.place_section_in_arena(
            text,
            SectionPlacement::new(LayoutArenaId::new(0), 0x1000, 64),
        );
        layout.place_section_in_arena(
            data,
            SectionPlacement::new(LayoutArenaId::new(1), 0x2000, 64),
        );

        assert_eq!(
            resolve_relocation_site_address(&layout, ROOT_MODULE, Some(text), 0x1018,),
            Some(LayoutAddress::new(LayoutArenaId::new(0), 0x1018))
        );
        assert_eq!(
            resolve_relocation_site_address(&layout, ROOT_MODULE, Some(text), 0x2018,),
            None
        );
    }
}
