use super::layout::{LayoutAddress, LayoutArenaId, LayoutSectionId, MemoryLayoutPlan};
use crate::linker::plan::{LinkModuleId, LinkPlan};
use crate::{
    ByteRepr, Result,
    elf::{
        ElfDyn, ElfDynamicTag, ElfPhdr, ElfPhdrs, ElfProgramType, ElfRelType, ElfSectionType,
        ElfSymbol,
    },
    image::{LoadedMemorySlice, RawDylib, ScannedDylib, ScannedSectionId},
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

#[derive(Clone, Copy)]
struct RuntimeSection {
    scanned: ScannedSectionId,
    section: LayoutSectionId,
    arena: LayoutArenaId,
    arena_offset: usize,
    original_address: usize,
    size: usize,
    actual_address: usize,
    module_offset: usize,
}

impl RuntimeSection {
    fn section_offset_for_original_address(self, original_address: usize) -> Option<usize> {
        if self.size == 0 {
            return None;
        }

        let delta = original_address.checked_sub(self.original_address)?;
        (delta < self.size).then_some(delta)
    }

    fn section_offset_for_layout_address(self, address: LayoutAddress) -> Option<usize> {
        if self.size == 0 || self.arena != address.arena() {
            return None;
        }

        let delta = address.offset().checked_sub(self.arena_offset)?;
        (delta < self.size).then_some(delta)
    }

    fn remap_original_address(self, original_address: usize) -> Option<usize> {
        if self.size == 0 && original_address == self.original_address {
            return Some(self.module_offset);
        }

        let delta = original_address.checked_sub(self.original_address)?;
        (delta < self.size).then_some(self.module_offset + delta)
    }

    fn remap_relocation_offset(self, original_offset: usize) -> Option<usize> {
        if let Some(offset) = self.remap_original_address(original_offset) {
            return Some(offset);
        }

        (original_offset < self.size).then_some(self.module_offset + original_offset)
    }

    fn memory_slice(self) -> LoadedMemorySlice {
        LoadedMemorySlice::new(self.actual_address, self.size)
    }
}

struct RuntimeModuleMemory {
    base: usize,
    segments: ElfSegments,
    memory_slices: Box<[LoadedMemorySlice]>,
    sections: Box<[RuntimeSection]>,
}

impl RuntimeModuleMemory {
    fn section_by_layout(&self, section: LayoutSectionId) -> Option<RuntimeSection> {
        self.sections
            .iter()
            .find(|candidate| candidate.section == section)
            .copied()
    }

    fn section_by_scanned(&self, scanned: ScannedSectionId) -> Option<RuntimeSection> {
        self.sections
            .iter()
            .find(|candidate| candidate.scanned == scanned)
            .copied()
    }

    fn remap_original_address(&self, original_address: usize) -> Option<usize> {
        self.sections
            .iter()
            .find_map(|section| section.remap_original_address(original_address))
    }

    fn remap_symbol_value(&self, symbol: &ElfSymbol) -> Option<usize> {
        let section_index = symbol.st_shndx();
        if section_index == SHN_UNDEF as usize || section_index == SHN_ABS as usize {
            return Some(symbol.st_value());
        }

        let section = self.section_by_scanned(ScannedSectionId::new(section_index))?;
        section
            .remap_original_address(symbol.st_value())
            .or_else(|| {
                (symbol.st_value() < section.size)
                    .then_some(section.module_offset + symbol.st_value())
            })
    }

    fn remap_runtime_relocation_offset(
        &self,
        target: Option<LayoutSectionId>,
        original_offset: usize,
    ) -> Option<usize> {
        target
            .and_then(|section_id| self.section_by_layout(section_id))
            .and_then(|section| section.remap_relocation_offset(original_offset))
            .or_else(|| self.remap_original_address(original_offset))
    }

    fn section_offset_for_original_address(
        &self,
        original_address: usize,
    ) -> Option<(LayoutSectionId, usize)> {
        self.sections.iter().find_map(|section| {
            section
                .section_offset_for_original_address(original_address)
                .map(|offset| (section.section, offset))
        })
    }

    fn section_offset_for_layout_address(
        &self,
        address: LayoutAddress,
    ) -> Option<(LayoutSectionId, usize)> {
        self.sections.iter().find_map(|section| {
            section
                .section_offset_for_layout_address(address)
                .map(|offset| (section.section, offset))
        })
    }
}

#[derive(Clone, Copy)]
struct RuntimeRewriteSection {
    layout: LayoutSectionId,
    symbol_table: bool,
    allocated_relocation: bool,
}

struct RuntimeMetadataRewriter<'a, K, D: 'static> {
    sections: Box<[RuntimeRewriteSection]>,
    dynamic_range: (usize, usize),
    plan: &'a mut LinkPlan<K, D>,
    runtime: &'a RuntimeModuleMemory,
}

impl<'a, K, D> RuntimeMetadataRewriter<'a, K, D>
where
    K: Clone + Ord,
    D: 'static,
{
    fn new(
        sections: Box<[RuntimeRewriteSection]>,
        dynamic_range: (usize, usize),
        plan: &'a mut LinkPlan<K, D>,
        runtime: &'a RuntimeModuleMemory,
    ) -> Self {
        Self {
            sections,
            dynamic_range,
            plan,
            runtime,
        }
    }

    fn rewrite(&mut self) -> Result<()> {
        self.rewrite_symbol_tables()?;
        self.rewrite_allocated_relocation_sections()?;
        self.rewrite_dynamic_section()?;
        Ok(())
    }

    fn rewrite_symbol_tables(&mut self) -> Result<()> {
        for section in self.sections.iter().copied() {
            if !section.symbol_table {
                continue;
            }
            let Some(bytes) = self.plan.section_bytes_mut(section.layout)? else {
                continue;
            };
            let symbols = typed_slice_mut::<ElfSymbol>(bytes)?;
            for elf_symbol in symbols {
                if let Some(value) = self.runtime.remap_symbol_value(elf_symbol) {
                    elf_symbol.set_value(value);
                }
            }
        }

        Ok(())
    }

    fn rewrite_allocated_relocation_sections(&mut self) -> Result<()> {
        for section in self.sections.iter().copied() {
            if !section.allocated_relocation {
                continue;
            }
            if self.runtime.section_by_layout(section.layout).is_none() {
                continue;
            }
            let Some(relocation) = self
                .plan
                .memory_layout()
                .section_metadata(section.layout)
                .info_section()
            else {
                return Err(crate::custom_error(
                    "retained relocation section is missing relocation metadata",
                ));
            };
            let Some(bytes) = self.plan.section_bytes_mut(section.layout)? else {
                continue;
            };
            let rels = typed_slice_mut::<ElfRelType>(bytes)?;
            for rel in rels {
                if let Some(offset) = self
                    .runtime
                    .remap_runtime_relocation_offset(Some(relocation), rel.r_offset())
                {
                    rel.set_offset(offset);
                }
            }
        }

        Ok(())
    }

    fn rewrite_dynamic_section(&mut self) -> Result<()> {
        let (dynamic_address, dynamic_size) = self.dynamic_range;
        let (section_id, section_offset) = self
            .runtime
            .section_offset_for_original_address(dynamic_address)
            .ok_or_else(|| {
                crate::custom_error("failed to remap PT_DYNAMIC into arena-backed memory")
            })?;
        let bytes = self.plan.section_bytes_mut(section_id)?.ok_or_else(|| {
            crate::custom_error("arena-backed PT_DYNAMIC section data is missing")
        })?;
        let end = section_offset
            .checked_add(dynamic_size)
            .ok_or_else(|| crate::custom_error("arena-backed PT_DYNAMIC range overflowed"))?;
        let dyns =
            typed_slice_mut::<ElfDyn>(bytes.get_mut(section_offset..end).ok_or_else(|| {
                crate::custom_error("arena-backed PT_DYNAMIC range exceeds section data")
            })?)?;
        for dyn_ in dyns {
            if let Some(rewritten) = remap_dynamic_value(self.runtime, dyn_.tag(), dyn_.value()) {
                dyn_.set_value(rewritten);
            }
            if dyn_.tag() == ElfDynamicTag::NULL {
                break;
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
    apply_retained_relocations(module_id, plan, &runtime, mapped_section_arenas)?;
    let (sections, dynamic_range) = {
        let scanned = plan
            .scanned_module(module_id)
            .ok_or_else(|| crate::custom_error("arena-backed module is missing scan metadata"))?;
        let dynamic = program_header(scanned.phdrs(), ElfProgramType::DYNAMIC)
            .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
        (
            collect_rewrite_sections(module_id, scanned, plan.memory_layout()),
            (dynamic.p_vaddr(), dynamic.p_memsz()),
        )
    };
    let mut rewriter = RuntimeMetadataRewriter::new(sections, dynamic_range, plan, &runtime);
    rewriter.rewrite()
}

fn collect_rewrite_sections<D>(
    module_id: LinkModuleId,
    scanned: &ScannedDylib<D>,
    layout: &MemoryLayoutPlan,
) -> Box<[RuntimeRewriteSection]>
where
    D: 'static,
{
    scanned
        .sections()
        .filter_map(|section| {
            let layout = layout.module_section_id(module_id, section.id())?;
            Some(RuntimeRewriteSection {
                layout,
                symbol_table: matches!(
                    section.section_type(),
                    ElfSectionType::SYMTAB | ElfSectionType::DYNSYM
                ),
                allocated_relocation: section.is_allocated() && section.is_relocation_section(),
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
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
    let dynamic_ptr = dynamic_ptr(&original_phdrs, &runtime)?;
    let eh_frame_hdr = eh_frame_hdr(&original_phdrs, &runtime);
    let tls_info = tls_info(&original_phdrs, &runtime);
    let entry = remap_entry(scanned.ehdr().e_entry(), &runtime);
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

    let mut sections = Vec::with_capacity(module.alloc_sections().len());
    for section_id in module.alloc_sections().iter().copied() {
        let Some(placement) = layout.section_placement(section_id) else {
            continue;
        };
        let metadata = layout.section_metadata(section_id);
        let scanned_id = metadata.scanned_section();
        let arena = mapped_section_arenas
            .get(placement.arena())
            .ok_or_else(|| {
                crate::custom_error("arena-backed module referenced an unmapped arena")
            })?;
        sections.push(RuntimeSection {
            scanned: scanned_id,
            section: section_id,
            arena: placement.arena(),
            arena_offset: placement.offset(),
            original_address: metadata.original_address(),
            size: metadata.size(),
            actual_address: arena.address(placement.offset()).ok_or_else(|| {
                crate::custom_error("arena-backed module section address overflowed")
            })?,
            module_offset: 0,
        });
    }

    let Some(base) = sections.iter().map(|section| section.actual_address).min() else {
        return Err(crate::custom_error(
            "arena-backed module does not own any alloc sections",
        ));
    };

    for section in &mut sections {
        section.module_offset = section.actual_address - base;
    }

    let mut segment_slices = Vec::with_capacity(sections.len());
    let mut memory_slices = sections
        .iter()
        .map(|section| section.memory_slice())
        .collect::<Vec<_>>();
    memory_slices.sort_unstable_by_key(|slice| slice.base());

    for section in &sections {
        let arena = mapped_section_arenas.get(section.arena).ok_or_else(|| {
            crate::custom_error("arena-backed module referenced an unmapped arena")
        })?;
        segment_slices.push(ElfSegments::slice(
            section.module_offset,
            section.size,
            arena.backing(),
        ));
    }

    Ok(RuntimeModuleMemory {
        base,
        segments: ElfSegments::from_slices(base, segment_slices),
        memory_slices: memory_slices.into_boxed_slice(),
        sections: sections.into_boxed_slice(),
    })
}

fn apply_retained_relocations<K, D>(
    module_id: LinkModuleId,
    plan: &mut LinkPlan<K, D>,
    runtime: &RuntimeModuleMemory,
    mapped_section_arenas: &MappedArenaMap,
) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let repairs = {
        let derived = plan
            .memory_layout()
            .module_derived(module_id)
            .ok_or_else(|| {
                crate::custom_error("arena-backed module is missing derived relocation state")
            })?;
        derived
            .relocation_repairs()
            .map(|(_, relocation)| relocation.clone())
            .collect::<Vec<_>>()
    };

    for relocation in repairs {
        let Some(symbol_table_section) = relocation.symbol_table_section() else {
            continue;
        };

        for site in relocation.sites() {
            let Some(actual_site) = mapped_section_arenas.address(site.address()) else {
                continue;
            };
            let Some((section_id, section_offset)) =
                runtime.section_offset_for_layout_address(site.address())
            else {
                continue;
            };
            let symbol_value = {
                let Some(symbol) =
                    symbol_from_table(symbol_table_section, site.symbol_index(), plan)?
                else {
                    continue;
                };
                runtime
                    .remap_symbol_value(symbol)
                    .unwrap_or_else(|| symbol.st_value())
            };
            let value = rewrite_relocation_value(
                site.relocation_type(),
                symbol_value,
                site.addend(),
                actual_site - runtime.base,
            )?;
            let Some(bytes) = plan.section_bytes_mut(section_id)? else {
                continue;
            };
            write_relocation_value(bytes, section_offset, value)?;
        }
    }

    Ok(())
}

fn dynamic_ptr(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Result<NonNull<ElfDyn>> {
    let phdr = program_header(phdrs, ElfProgramType::DYNAMIC)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
    let offset = runtime
        .remap_original_address(phdr.p_vaddr())
        .ok_or_else(|| crate::custom_error("failed to remap PT_DYNAMIC"))?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
        .ok_or_else(|| crate::custom_error("PT_DYNAMIC remapped to a null pointer"))
}

fn eh_frame_hdr(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Option<NonNull<u8>> {
    let phdr = program_header(phdrs, ElfProgramType::GNU_EH_FRAME)?;
    let offset = runtime.remap_original_address(phdr.p_vaddr())?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
}

fn tls_info(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Option<TlsInfo> {
    let phdr = program_header(phdrs, ElfProgramType::TLS)?;
    let offset = runtime.remap_original_address(phdr.p_vaddr())?;
    let image = runtime.segments.get_slice::<u8>(offset, phdr.p_filesz());
    Some(TlsInfo::new(phdr, image))
}

fn remap_entry(
    original_entry: usize,
    runtime: &RuntimeModuleMemory,
) -> crate::relocation::RelocAddr {
    runtime
        .remap_original_address(original_entry)
        .map(|offset| runtime.segments.base_addr().offset(offset))
        .unwrap_or_else(|| runtime.segments.base_addr().offset(original_entry))
}

fn symbol_from_table<'a, K, D>(
    section: LayoutSectionId,
    symbol_index: usize,
    plan: &'a mut LinkPlan<K, D>,
) -> Result<Option<&'a ElfSymbol>>
where
    K: Clone + Ord,
    D: 'static,
{
    let Some(data) = plan.section_data(section)? else {
        return Ok(None);
    };
    let bytes = data.bytes().ok_or_else(|| {
        crate::custom_error("retained relocation symbol table cannot be zero-fill")
    })?;
    let symbols = typed_slice::<ElfSymbol>(bytes)?;
    Ok(symbols.get(symbol_index))
}

fn typed_slice<T: ByteRepr>(bytes: &[u8]) -> Result<&[T]> {
    try_cast_slice(bytes)
        .ok_or_else(|| crate::custom_error("section bytes do not match the requested type layout"))
}

fn typed_slice_mut<T: ByteRepr>(bytes: &mut [u8]) -> Result<&mut [T]> {
    try_cast_slice_mut(bytes)
        .ok_or_else(|| crate::custom_error("section bytes do not match the requested type layout"))
}

fn program_header(phdrs: &[ElfPhdr], kind: ElfProgramType) -> Option<&ElfPhdr> {
    phdrs.iter().find(|phdr| phdr.program_type() == kind)
}

fn remap_dynamic_value(
    runtime: &RuntimeModuleMemory,
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
        | ElfDynamicTag::VERDEF => runtime.remap_original_address(value),
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
