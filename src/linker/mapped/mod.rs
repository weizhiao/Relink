use super::layout::{MemoryLayoutPlan, SectionId};
use crate::linker::mapped::rewrite::RuntimeMetadataRewriter;
use crate::linker::plan::{LinkPlan, ModuleId};
use crate::{
    LinkerError, Result,
    elf::{ElfDyn, ElfPhdrs, ElfProgramType},
    entity::SecondaryMap,
    image::{RawDylib, ScannedDylib},
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
}

#[derive(Default)]
pub(crate) struct MappedRuntimeMemory {
    arenas: MappedArenaMap,
    modules: SecondaryMap<ModuleId, RuntimeModuleMemory>,
}

#[derive(Clone, Copy)]
struct RuntimeSectionMemory {
    section: SectionId,
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
        module_id: ModuleId,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap,
    ) -> Result<Self> {
        let module = layout.module(module_id);

        let mut placed_sections = Vec::with_capacity(module.alloc_sections().len());
        for section_id in module.alloc_sections().iter().copied() {
            let Some(placement) = layout.placement(section_id) else {
                continue;
            };
            let metadata = layout.section(section_id);
            let arena = mapped_section_arenas
                .get(placement.arena())
                .ok_or_else(|| {
                    LinkerError::runtime_memory("arena-backed module referenced an unmapped arena")
                })?;
            let actual_address = arena.address(placement.offset()).ok_or_else(|| {
                LinkerError::runtime_memory("arena-backed module section address overflowed")
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
            return Err(LinkerError::runtime_memory(
                "arena-backed module does not own any alloc sections",
            )
            .into());
        };

        let mut segment_slices = Vec::with_capacity(placed_sections.len());
        let mut runtime_sections = Vec::with_capacity(placed_sections.len());

        for (section, layout_address, source_address, actual_address, size) in &placed_sections {
            let arena = mapped_section_arenas
                .get(layout_address.arena())
                .ok_or_else(|| {
                    LinkerError::runtime_memory("arena-backed module referenced an unmapped arena")
                })?;
            let runtime_offset = actual_address.checked_sub(base).ok_or_else(|| {
                LinkerError::runtime_memory("arena-backed module address precedes runtime base")
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
        })
    }

    fn remap_source_address(&self, source_address: usize) -> Option<usize> {
        self.sections.iter().copied().find_map(|section| {
            section
                .source_offset(source_address)
                .map(|offset| section.runtime_offset + offset)
        })
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
        module_id: ModuleId,
        layout: &MemoryLayoutPlan,
    ) -> Result<&RuntimeModuleMemory> {
        if self.modules.contains_key(module_id) {
            return Err(LinkerError::runtime_memory(
                "section-region module runtime memory was built more than once",
            )
            .into());
        }
        let runtime = RuntimeModuleMemory::build(module_id, layout, &self.arenas)?;
        let _ = self.modules.insert(module_id, runtime);
        self.modules
            .get(module_id)
            .ok_or_else(|| {
                LinkerError::runtime_memory("section-region module runtime memory was not cached")
            })
            .map_err(Into::into)
    }

    pub(crate) fn repair_module<K, D>(
        &mut self,
        module_id: ModuleId,
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

    pub(crate) fn take_module(&mut self, module_id: ModuleId) -> Result<RuntimeModuleMemory> {
        self.modules
            .remove(module_id)
            .ok_or_else(|| {
                LinkerError::runtime_memory("section-region planned load is missing runtime memory")
            })
            .map_err(Into::into)
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
    let mut dynamic_ptr: Option<NonNull<ElfDyn>> = None;
    let mut eh_frame_hdr: Option<NonNull<u8>> = None;
    let mut tls_info: Option<TlsInfo> = None;

    for phdr in &original_phdrs {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                let offset = runtime
                    .remap_source_address(phdr.p_vaddr())
                    .ok_or_else(|| LinkerError::runtime_memory("failed to remap PT_DYNAMIC"))?;
                dynamic_ptr = Some(
                    NonNull::new(runtime.segments.get_mut_ptr(offset)).ok_or_else(|| {
                        LinkerError::runtime_memory("PT_DYNAMIC remapped to a null pointer")
                    })?,
                );
            }
            ElfProgramType::GNU_EH_FRAME => {
                let offset = runtime
                    .remap_source_address(phdr.p_vaddr())
                    .ok_or_else(|| {
                        LinkerError::runtime_memory("failed to remap PT_GNU_EH_FRAME")
                    })?;
                eh_frame_hdr = Some(
                    NonNull::new(runtime.segments.get_mut_ptr(offset)).ok_or_else(|| {
                        LinkerError::runtime_memory("PT_GNU_EH_FRAME remapped to a null pointer")
                    })?,
                );
            }
            ElfProgramType::TLS => {
                let offset = runtime
                    .remap_source_address(phdr.p_vaddr())
                    .ok_or_else(|| LinkerError::runtime_memory("failed to remap PT_TLS"))?;
                let image = runtime.segments.get_slice::<u8>(offset, phdr.p_filesz());
                tls_info = Some(TlsInfo::new(phdr, image));
            }
            _ => {}
        }
    }

    let dynamic_ptr = dynamic_ptr
        .ok_or_else(|| LinkerError::runtime_memory("arena-backed module is missing PT_DYNAMIC"))?;
    let original_entry = scanned.ehdr().e_entry();
    let entry = runtime
        .remap_source_address(original_entry)
        .map(|offset| runtime.segments.base_addr().offset(offset))
        .unwrap_or_else(|| runtime.segments.base_addr().offset(original_entry));
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
        init_fn,
        fini_fn,
        user_data,
    })
}
