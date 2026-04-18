use super::layout::{LayoutAddress, LayoutSectionId, MemoryLayoutPlan};
use crate::linker::plan::{LinkModuleId, LinkPlan};
use crate::{
    RelocationError, Result,
    arch::{Architecture, REL_NONE},
    elf::{ElfDyn, ElfDynamicTag, ElfPhdr, ElfPhdrs, ElfProgramType, ElfRelType, ElfSymbol},
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

struct RuntimeModuleMemory {
    sections: Box<[RuntimeSectionMemory]>,
    segments: ElfSegments,
    memory_slices: Box<[LoadedMemorySlice]>,
}

#[derive(Clone, Copy)]
struct RuntimeSectionMemory {
    section: LayoutSectionId,
    source_address: usize,
    layout_address: LayoutAddress,
    runtime_offset: usize,
    size: usize,
}

struct RuntimeRelocationSite {
    place: usize,
    section: LayoutSectionId,
    section_offset: usize,
}

impl RuntimeSectionMemory {
    fn source_offset(self, source_address: usize) -> Option<usize> {
        let offset = source_address.checked_sub(self.source_address)?;
        if self.size == 0 {
            return (offset == 0).then_some(0);
        }
        (offset < self.size).then_some(offset)
    }

    fn layout_address(self, source_address: usize) -> Option<LayoutAddress> {
        self.layout_address
            .checked_add(self.source_offset(source_address)?)
    }

    fn section_offset_for_layout_address(self, address: LayoutAddress) -> Option<usize> {
        if self.layout_address.arena() != address.arena() {
            return None;
        }
        let offset = address.offset().checked_sub(self.layout_address.offset())?;
        if self.size == 0 {
            return (offset == 0).then_some(0);
        }
        (offset < self.size).then_some(offset)
    }
}

impl RuntimeModuleMemory {
    fn section(&self, section: LayoutSectionId) -> Option<RuntimeSectionMemory> {
        self.sections
            .iter()
            .copied()
            .find(|runtime_section| runtime_section.section == section)
    }

    fn layout_address_for_source_address(
        &self,
        target_section: Option<LayoutSectionId>,
        source_address: usize,
    ) -> Option<LayoutAddress> {
        if let Some(section) = target_section {
            return self.section(section)?.layout_address(source_address);
        }

        self.sections
            .iter()
            .copied()
            .find_map(|section| section.layout_address(source_address))
    }

    fn remap_source_address(&self, source_address: usize) -> Result<Option<usize>> {
        Ok(self.sections.iter().copied().find_map(|section| {
            section
                .source_offset(source_address)
                .map(|offset| section.runtime_offset + offset)
        }))
    }

    fn remap_symbol_value(&self, section: Option<LayoutSectionId>, value: usize) -> Result<usize> {
        let Some(section_id) = section else {
            return Ok(value);
        };
        let Some(section) = self.section(section_id) else {
            return Err(crate::custom_error(
                "arena-backed symbol value referenced an unplaced section",
            ));
        };
        if let Some(offset) = section.source_offset(value) {
            return Ok(section.runtime_offset + offset);
        }
        Err(crate::custom_error(
            "arena-backed symbol value does not map into its target section",
        ))
    }

    fn remap_relocation_offset(
        &self,
        target: Option<LayoutSectionId>,
        original_offset: usize,
    ) -> Result<usize> {
        if let Some(section) = target {
            let Some(section) = self.section(section) else {
                return Err(crate::custom_error(
                    "allocated relocation entry target section is not arena-backed",
                ));
            };
            if let Some(offset) = section.source_offset(original_offset) {
                return Ok(section.runtime_offset + offset);
            }

            return Err(crate::custom_error(
                "allocated relocation entry offset does not map into its target section",
            ));
        }

        self.remap_source_address(original_offset)?.ok_or_else(|| {
            crate::custom_error(
                "allocated relocation entry offset does not map into arena-backed memory",
            )
        })
    }

    fn retained_relocation_site(
        &self,
        target_section: LayoutSectionId,
        source_address: usize,
    ) -> Result<RuntimeRelocationSite> {
        let section = self.section(target_section).ok_or_else(|| {
            crate::custom_error("retained relocation target section is not arena-backed")
        })?;
        let section_offset = section.source_offset(source_address).ok_or_else(|| {
            crate::custom_error("retained relocation offset does not map into its target section")
        })?;
        let place = section
            .runtime_offset
            .checked_add(section_offset)
            .ok_or_else(|| crate::custom_error("arena-backed runtime offset overflowed"))?;

        Ok(RuntimeRelocationSite {
            place,
            section: target_section,
            section_offset,
        })
    }

    fn section_offset_for_source_address(
        &self,
        source_address: usize,
    ) -> Option<(LayoutSectionId, usize)> {
        let address = self.layout_address_for_source_address(None, source_address)?;
        self.section_offset_for_layout_address(address)
    }

    fn section_offset_for_layout_address(
        &self,
        address: LayoutAddress,
    ) -> Option<(LayoutSectionId, usize)> {
        self.sections.iter().copied().find_map(|section| {
            section
                .section_offset_for_layout_address(address)
                .map(|offset| (section.section, offset))
        })
    }
}

fn symbol_section_id(
    module_id: LinkModuleId,
    layout: &MemoryLayoutPlan,
    section_index: usize,
) -> Result<Option<LayoutSectionId>> {
    if section_index == SHN_UNDEF as usize || section_index == SHN_ABS as usize {
        return Ok(None);
    }

    layout
        .module_section_id(module_id, ScannedSectionId::new(section_index))
        .map(Some)
        .ok_or_else(|| {
            crate::custom_error("arena-backed symbol value referenced an unmapped section")
        })
}

struct RuntimeMetadataRewriter<'a, K, D: 'static> {
    module_id: LinkModuleId,
    plan: &'a mut LinkPlan<K, D>,
    runtime: &'a RuntimeModuleMemory,
}

struct RetainedRelocationRewrite {
    section: LayoutSectionId,
    section_offset: usize,
    value: RetainedRelocationValue,
}

struct RetainedRelocationValue {
    bytes: [u8; core::mem::size_of::<usize>()],
    len: usize,
}

impl RetainedRelocationValue {
    fn from_bytes<const N: usize>(bytes: [u8; N]) -> Self {
        let mut stored = [0; core::mem::size_of::<usize>()];
        stored[..N].copy_from_slice(&bytes);
        Self {
            bytes: stored,
            len: N,
        }
    }

    fn usize(value: usize) -> Self {
        Self::from_bytes(value.to_ne_bytes())
    }

    fn u32(value: u32) -> Self {
        Self::from_bytes(value.to_ne_bytes())
    }

    fn i32(value: i32) -> Self {
        Self::from_bytes(value.to_ne_bytes())
    }

    fn write_to(self, section_bytes: &mut [u8], section_offset: usize) -> Result<()> {
        write_relocation_bytes(section_bytes, section_offset, &self.bytes[..self.len])
    }
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
    ) -> Self {
        Self {
            module_id,
            plan,
            runtime,
        }
    }

    fn rewrite(&mut self) -> Result<()> {
        self.rewrite_symbol_tables()?;
        self.rewrite_retained_relocations()?;
        self.rewrite_allocated_relocation_sections()?;
        self.rewrite_dynamic_section()?;
        Ok(())
    }

    fn rewrite_retained_relocations(&mut self) -> Result<()> {
        let relocation_sections = {
            let layout = self.plan.memory_layout();
            layout
                .module(self.module_id)
                .relocation_sections()
                .iter()
                .copied()
                .filter(|section| !layout.section_metadata(*section).is_allocated_relocation())
                .collect::<Vec<_>>()
        };

        for relocation_section in relocation_sections {
            self.rewrite_retained_relocation_section(relocation_section)?;
        }

        Ok(())
    }

    fn rewrite_retained_relocation_section(
        &mut self,
        relocation_section: LayoutSectionId,
    ) -> Result<()> {
        let symbol_table_section = self
            .plan
            .memory_layout()
            .section_metadata(relocation_section)
            .linked_section()
            .ok_or_else(|| {
                crate::custom_error(
                    "retained relocation section is missing its linked symbol table",
                )
            })?;

        let _ = self.plan.section_data(symbol_table_section)?;
        let runtime = self.runtime;
        let rewrites = {
            let (data, layout) = self.plan.section_data_with_layout(relocation_section)?;
            let target_section = layout
                .section_metadata(relocation_section)
                .info_section()
                .ok_or_else(|| {
                    crate::custom_error("retained relocation section is missing its target section")
                })?;
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
                if let Some(rewrite) =
                    retained_relocation_rewrite(runtime, target_section, entry, symbols)?
                {
                    rewrites.push(rewrite);
                }
            }
            rewrites
        };

        for rewrite in rewrites {
            let data = self.plan.section_data_mut(rewrite.section)?;
            rewrite
                .value
                .write_to(data.as_bytes_mut(), rewrite.section_offset)?;
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
            let symbol_sections = {
                let (data, layout) = self.plan.section_data_with_layout(section)?;
                let mut symbol_sections = Vec::new();
                data.try_for_each(|_, symbol: &ElfSymbol| -> Result<()> {
                    let symbol_section =
                        symbol_section_id(self.module_id, layout, symbol.st_shndx())?;
                    symbol_sections.push(symbol_section);
                    Ok(())
                })
                .ok_or_else(|| {
                    crate::custom_error("section bytes do not match the requested type layout")
                })??;
                symbol_sections
            };

            let data = self.plan.section_data_mut(section)?;
            data.try_for_each_mut(|index, symbol: &mut ElfSymbol| -> Result<()> {
                let symbol_section = symbol_sections[index];
                let value = self
                    .runtime
                    .remap_symbol_value(symbol_section, symbol.st_value())?;
                symbol.set_value(value);
                Ok(())
            })
            .ok_or_else(|| {
                crate::custom_error("section bytes do not match the requested type layout")
            })??;
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
            let relocation = self
                .plan
                .memory_layout()
                .section_metadata(section)
                .info_section();
            let data = self.plan.section_data_mut(section)?;
            data.try_for_each_mut(|_, rel: &mut ElfRelType| -> Result<()> {
                if rel.r_type() as u32 == REL_NONE {
                    return Ok(());
                }
                let offset = self
                    .runtime
                    .remap_relocation_offset(relocation, rel.r_offset())?;
                rel.set_offset(offset);
                Ok(())
            })
            .ok_or_else(|| {
                crate::custom_error("section bytes do not match the requested type layout")
            })??;
        }

        Ok(())
    }

    fn rewrite_dynamic_section(&mut self) -> Result<()> {
        let (dynamic_address, dynamic_size) = dynamic_range(self.module_id, self.plan)?;
        let (section_id, section_offset) = self
            .runtime
            .section_offset_for_source_address(dynamic_address)
            .ok_or_else(|| {
                crate::custom_error("failed to remap PT_DYNAMIC into arena-backed memory")
            })?;
        let end = section_offset
            .checked_add(dynamic_size)
            .ok_or_else(|| crate::custom_error("arena-backed PT_DYNAMIC range overflowed"))?;

        let rewrites = {
            let data = self.plan.section_data(section_id)?;
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
                if let Some(value) = remap_dynamic_value(self.runtime, tag, dyn_.value())? {
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
    let mut rewriter = RuntimeMetadataRewriter::new(module_id, plan, &runtime);
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
    let dynamic_ptr = dynamic_ptr(&original_phdrs, &runtime)?;
    let eh_frame_hdr = eh_frame_hdr(&original_phdrs, &runtime)?;
    let tls_info = tls_info(&original_phdrs, &runtime)?;
    let entry = remap_entry(scanned.ehdr().e_entry(), &runtime)?;
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
        placed_sections.push((
            section_id,
            placement.address(),
            metadata.source_address(),
            actual_address,
            metadata.size(),
        ));
    }

    let Some(base) = placed_sections
        .iter()
        .map(|(_, _, _, actual_address, _)| *actual_address)
        .min()
    else {
        return Err(crate::custom_error(
            "arena-backed module does not own any alloc sections",
        ));
    };

    let mut segment_slices = Vec::with_capacity(placed_sections.len());
    let mut memory_slices = placed_sections
        .iter()
        .map(|(_, _, _, actual_address, size)| LoadedMemorySlice::new(*actual_address, *size))
        .collect::<Vec<_>>();
    memory_slices.sort_unstable_by_key(|slice| slice.base());
    let mut runtime_sections = Vec::with_capacity(placed_sections.len());

    for (section, layout_address, source_address, actual_address, size) in &placed_sections {
        let arena = mapped_section_arenas
            .get(layout_address.arena())
            .ok_or_else(|| {
                crate::custom_error("arena-backed module referenced an unmapped arena")
            })?;
        let runtime_offset = actual_address.checked_sub(base).ok_or_else(|| {
            crate::custom_error("arena-backed module address precedes runtime base")
        })?;
        segment_slices.push(ElfSegments::slice(runtime_offset, *size, arena.backing()));
        runtime_sections.push(RuntimeSectionMemory {
            section: *section,
            source_address: *source_address,
            layout_address: *layout_address,
            runtime_offset,
            size: *size,
        });
    }

    Ok(RuntimeModuleMemory {
        sections: runtime_sections.into_boxed_slice(),
        segments: ElfSegments::from_slices(base, segment_slices),
        memory_slices: memory_slices.into_boxed_slice(),
    })
}

fn dynamic_ptr(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Result<NonNull<ElfDyn>> {
    let phdr = program_header(phdrs, ElfProgramType::DYNAMIC)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
    let offset = runtime
        .remap_source_address(phdr.p_vaddr())?
        .ok_or_else(|| crate::custom_error("failed to remap PT_DYNAMIC"))?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
        .ok_or_else(|| crate::custom_error("PT_DYNAMIC remapped to a null pointer"))
}

fn eh_frame_hdr(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Result<Option<NonNull<u8>>> {
    let Some(phdr) = program_header(phdrs, ElfProgramType::GNU_EH_FRAME) else {
        return Ok(None);
    };
    let Some(offset) = runtime.remap_source_address(phdr.p_vaddr())? else {
        return Ok(None);
    };
    Ok(NonNull::new(runtime.segments.get_mut_ptr(offset)))
}

fn tls_info(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Result<Option<TlsInfo>> {
    let Some(phdr) = program_header(phdrs, ElfProgramType::TLS) else {
        return Ok(None);
    };
    let Some(offset) = runtime.remap_source_address(phdr.p_vaddr())? else {
        return Ok(None);
    };
    let image = runtime.segments.get_slice::<u8>(offset, phdr.p_filesz());
    Ok(Some(TlsInfo::new(phdr, image)))
}

fn remap_entry(
    original_entry: usize,
    runtime: &RuntimeModuleMemory,
) -> Result<crate::relocation::RelocAddr> {
    Ok(runtime
        .remap_source_address(original_entry)?
        .map(|offset| runtime.segments.base_addr().offset(offset))
        .unwrap_or_else(|| runtime.segments.base_addr().offset(original_entry)))
}

fn program_header(phdrs: &[ElfPhdr], kind: ElfProgramType) -> Option<&ElfPhdr> {
    phdrs.iter().find(|phdr| phdr.program_type() == kind)
}

fn remap_dynamic_value(
    runtime: &RuntimeModuleMemory,
    tag: ElfDynamicTag,
    value: usize,
) -> Result<Option<usize>> {
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
        | ElfDynamicTag::VERDEF => runtime.remap_source_address(value),
        _ => Ok(None),
    }
}

fn retained_relocation_rewrite(
    runtime: &RuntimeModuleMemory,
    target_section: LayoutSectionId,
    entry: &ElfRelType,
    symbols: &[ElfSymbol],
) -> Result<Option<RetainedRelocationRewrite>> {
    if entry.r_type() as u32 == REL_NONE {
        return Ok(None);
    }

    let site = runtime.retained_relocation_site(target_section, entry.r_offset())?;
    let symbol = symbols.get(entry.r_symbol()).ok_or_else(|| {
        crate::custom_error("retained relocation references a missing symbol table entry")
    })?;
    // Symbol tables are rewritten first, so st_value is already in
    // arena-backed runtime coordinates here.
    let symbol_value = symbol.st_value();
    let addend = retained_relocation_addend(entry)?;
    let Some(value) = retained_relocation_value(entry.r_type(), symbol_value, addend, site.place)?
    else {
        return Ok(None);
    };

    Ok(Some(RetainedRelocationRewrite {
        section: site.section,
        section_offset: site.section_offset,
        value,
    }))
}

fn retained_relocation_addend(entry: &ElfRelType) -> Result<isize> {
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    {
        let _ = entry;
        Err(crate::custom_error(
            "arena-backed retained relocation repair requires explicit relocation addends",
        ))
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
    {
        Ok(entry.r_addend(0))
    }
}

fn retained_relocation_value(
    relocation_type: usize,
    symbol_value: usize,
    addend: isize,
    new_place: usize,
) -> core::result::Result<Option<RetainedRelocationValue>, RelocationError> {
    <Architecture as crate::relocation::RelocationValueProvider>::relocation_value(
        relocation_type,
        symbol_value,
        addend,
        new_place,
        |_| None,
        |value| Some(RetainedRelocationValue::usize(value.into_inner())),
        |value| Some(RetainedRelocationValue::u32(value.into_inner())),
        |value| Some(RetainedRelocationValue::i32(value.into_inner())),
    )
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

    fn zero_sized_alloc_section_with_address(
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
                0,
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

    fn runtime(text: LayoutSectionId, data: LayoutSectionId) -> RuntimeModuleMemory {
        RuntimeModuleMemory {
            sections: Vec::from([
                RuntimeSectionMemory {
                    section: text,
                    source_address: 0x1000,
                    layout_address: LayoutAddress::new(LayoutArenaId::new(0), 0x1000),
                    runtime_offset: 0x1000,
                    size: 64,
                },
                RuntimeSectionMemory {
                    section: data,
                    source_address: 0x2000,
                    layout_address: LayoutAddress::new(LayoutArenaId::new(1), 0x2000),
                    runtime_offset: 0x2000,
                    size: 64,
                },
            ])
            .into_boxed_slice(),
            segments: ElfSegments::from_slices(0, Vec::new()),
            memory_slices: Vec::new().into_boxed_slice(),
        }
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
        let runtime = runtime(text, data);

        assert_eq!(
            runtime.layout_address_for_source_address(Some(text), 0x1018,),
            Some(LayoutAddress::new(LayoutArenaId::new(0), 0x1018))
        );
        assert_eq!(
            runtime.layout_address_for_source_address(Some(text), 0x2018,),
            None
        );
    }

    #[test]
    fn zero_sized_section_uses_its_base_address_as_an_anchor() {
        let mut layout = MemoryLayoutPlan::default();
        let anchor = zero_sized_alloc_section_with_address(
            &mut layout,
            5,
            ".anchor",
            LayoutMemoryClass::ReadOnlyData,
            0x3000,
        );
        let module = ModuleLayout::from_sections([(5, anchor)], layout.sections());
        layout.insert_module(ROOT_MODULE, module);
        layout.create_arena(LayoutArena::new(
            4096,
            LayoutMemoryClass::ReadOnlyData,
            LayoutArenaSharing::Shared,
        ));
        layout.place_section_in_arena(
            anchor,
            SectionPlacement::new(LayoutArenaId::new(0), 0x3000, 0),
        );
        let runtime = RuntimeModuleMemory {
            sections: Vec::from([RuntimeSectionMemory {
                section: anchor,
                source_address: 0x3000,
                layout_address: LayoutAddress::new(LayoutArenaId::new(0), 0x3000),
                runtime_offset: 0x3000,
                size: 0,
            }])
            .into_boxed_slice(),
            segments: ElfSegments::from_slices(0, Vec::new()),
            memory_slices: Vec::new().into_boxed_slice(),
        };

        let address = LayoutAddress::new(LayoutArenaId::new(0), 0x3000);

        assert_eq!(
            runtime.layout_address_for_source_address(Some(anchor), 0x3000),
            Some(address)
        );
        assert_eq!(
            runtime.section_offset_for_layout_address(address),
            Some((anchor, 0))
        );
        let site = runtime
            .retained_relocation_site(anchor, 0x3000)
            .expect("zero-sized anchor should resolve as a relocation site");
        assert_eq!(site.place, 0x3000);
        assert_eq!(site.section, anchor);
        assert_eq!(site.section_offset, 0);
    }

    #[test]
    fn symbol_section_id_errors_when_section_is_missing() {
        let mut layout = MemoryLayoutPlan::default();
        let section =
            alloc_section_with_address(&mut layout, 5, ".text", LayoutMemoryClass::Code, 0x1000);
        let module = ModuleLayout::from_sections([(5, section)], layout.sections());
        layout.insert_module(ROOT_MODULE, module);

        assert!(symbol_section_id(ROOT_MODULE, &layout, 6).is_err());
    }

    #[test]
    fn remap_symbol_value_errors_when_section_is_unplaced() {
        let mut layout = MemoryLayoutPlan::default();
        let section =
            alloc_section_with_address(&mut layout, 5, ".text", LayoutMemoryClass::Code, 0x1000);
        let module = ModuleLayout::from_sections([(5, section)], layout.sections());
        layout.insert_module(ROOT_MODULE, module);

        let runtime = RuntimeModuleMemory {
            sections: Vec::new().into_boxed_slice(),
            segments: ElfSegments::from_slices(0, Vec::new()),
            memory_slices: Vec::new().into_boxed_slice(),
        };
        let section_id = symbol_section_id(ROOT_MODULE, &layout, 5)
            .unwrap()
            .expect("section should be mapped in the layout");

        assert!(
            runtime
                .remap_symbol_value(Some(section_id), 0x1000)
                .is_err()
        );
    }
}
