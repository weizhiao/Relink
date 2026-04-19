use super::layout::{LayoutSectionId, MemoryLayoutPlan};
use crate::linker::mapped::rewrite::RuntimeMetadataRewriter;
use crate::linker::plan::{LinkModuleId, LinkPlan};
use crate::{
    Result,
    elf::{ElfDyn, ElfPhdr, ElfPhdrs, ElfProgramType},
    entity::SecondaryMap,
    image::{LoadedMemorySlice, RawDylib, ScannedDylib},
    loader::DynLifecycleHandler,
    os::Mmap,
    segment::ElfSegments,
    tls::{TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::ptr::NonNull;

mod arena;
mod rewrite;

use arena::MappedArenaMap;

pub(crate) struct RuntimeModuleMemory {
    sections: Box<[RuntimeSectionMemory]>,
    segments: ElfSegments,
    memory_slices: Box<[LoadedMemorySlice]>,
}

#[derive(Default)]
pub(crate) struct MappedRuntimeMemory {
    arenas: MappedArenaMap,
    modules: SecondaryMap<LinkModuleId, RuntimeModuleMemory>,
}

#[derive(Clone, Copy)]
struct RuntimeSectionMemory {
    section: LayoutSectionId,
    source_address: usize,
    runtime_offset: usize,
    size: usize,
}

impl RuntimeSectionMemory {
    fn source_offset(self, source_address: usize) -> Option<usize> {
        let offset = source_address.checked_sub(self.source_address)?;
        if self.size == 0 {
            return (offset == 0).then_some(0);
        }
        (offset < self.size).then_some(offset)
    }
}

impl RuntimeModuleMemory {
    fn build(
        module_id: LinkModuleId,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
    ) -> Result<Self> {
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
            let actual_address = arena.address(placement.offset()).ok_or_else(|| {
                crate::custom_error("arena-backed module section address overflowed")
            })?;
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

    fn remap_source_address(&self, source_address: usize) -> Result<Option<usize>> {
        Ok(self.sections.iter().copied().find_map(|section| {
            section
                .source_offset(source_address)
                .map(|offset| section.runtime_offset + offset)
        }))
    }
}

impl MappedRuntimeMemory {
    pub(crate) fn map<M, K, D>(plan: &LinkPlan<K, D>) -> Result<Option<Self>>
    where
        K: Clone + Ord,
        D: 'static,
        M: Mmap,
    {
        let Some(arenas) = MappedArenaMap::map_plan::<M, _, _>(plan)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            arenas,
            modules: SecondaryMap::default(),
        }))
    }

    fn build_module(
        &mut self,
        module_id: LinkModuleId,
        layout: &MemoryLayoutPlan,
    ) -> Result<&RuntimeModuleMemory> {
        if self.modules.contains_key(module_id) {
            return Err(crate::custom_error(
                "section-region module runtime memory was built more than once",
            ));
        }
        let runtime = RuntimeModuleMemory::build(module_id, layout, &self.arenas)?;
        let _ = self.modules.insert(module_id, runtime);
        self.modules.get(module_id).ok_or_else(|| {
            crate::custom_error("section-region module runtime memory was not cached")
        })
    }

    pub(crate) fn repair_module<K, D>(
        &mut self,
        module_id: LinkModuleId,
        plan: &mut LinkPlan<K, D>,
    ) -> Result<()>
    where
        K: Clone + Ord,
        D: 'static,
    {
        let runtime = self.build_module(module_id, plan.memory_layout())?;
        let mut rewriter = RuntimeMetadataRewriter::new(module_id, plan, runtime);
        rewriter.rewrite()
    }

    pub(crate) fn populate<K, D>(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()>
    where
        K: Clone + Ord,
        D: 'static,
    {
        self.arenas.populate(plan)
    }

    pub(crate) fn protect<M>(&self) -> Result<()>
    where
        M: Mmap,
    {
        self.arenas.protect::<M>()
    }

    pub(crate) fn take_module(&mut self, module_id: LinkModuleId) -> Result<RuntimeModuleMemory> {
        self.modules.remove(module_id).ok_or_else(|| {
            crate::custom_error("section-region planned load is missing runtime memory")
        })
    }
}

pub(crate) fn build_arena_raw_dylib<D, Tls>(
    mut scanned: ScannedDylib<D>,
    runtime: RuntimeModuleMemory,
    init_fn: DynLifecycleHandler,
    fini_fn: DynLifecycleHandler,
    force_static_tls: bool,
) -> Result<RawDylib<D>>
where
    D: Default + 'static,
    Tls: TlsResolver,
{
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
