use super::layout::{MemoryLayoutPlan, SectionId};
use crate::linker::mapped::rewrite::RuntimeMetadataRewriter;
use crate::linker::plan::{LinkPlan, ModuleId};
use crate::{
    LinkerError, Result,
    elf::{ElfDyn, ElfPhdrs, ElfProgramType},
    entity::SecondaryMap,
    image::{RawDynamic, ScannedDynamic},
    loader::DynLifecycleHandler,
    os::Mmap,
    relocation::{RelocationArch, RelocationValueProvider},
    segment::ElfSegments,
    tls::{TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::ptr::NonNull;

mod arena;
mod rewrite;

use arena::MappedArenaMap;
pub(crate) use rewrite::GotPltTarget;

pub(crate) struct RuntimeModuleMemory {
    sections: Box<[RuntimeSectionMemory]>,
    segments: ElfSegments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
struct SourceAddress(usize);

impl SourceAddress {
    #[inline]
    const fn new(address: usize) -> Self {
        Self(address)
    }

    #[inline]
    fn offset_from(self, base: Self) -> Option<usize> {
        self.0.checked_sub(base.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
struct RuntimeOffset(usize);

impl RuntimeOffset {
    #[inline]
    const fn new(offset: usize) -> Self {
        Self(offset)
    }

    #[inline]
    const fn get(self) -> usize {
        self.0
    }

    #[inline]
    fn checked_add(self, delta: usize) -> Option<Self> {
        self.0.checked_add(delta).map(Self)
    }
}

#[derive(Default)]
pub(crate) struct MappedRuntimeMemory {
    arenas: MappedArenaMap,
    modules: SecondaryMap<ModuleId, RuntimeModuleMemory>,
}

#[derive(Clone, Copy)]
struct RuntimeSectionMemory {
    section: SectionId,
    source_address: SourceAddress,
    runtime_offset: RuntimeOffset,
    size: usize,
}

impl RuntimeSectionMemory {
    fn source_offset(self, source_address: SourceAddress) -> Option<usize> {
        let offset = source_address.offset_from(self.source_address)?;
        if self.size == 0 {
            return (offset == 0).then_some(0);
        }
        (offset < self.size).then_some(offset)
    }

    fn runtime_offset(self, source_address: SourceAddress) -> Option<RuntimeOffset> {
        self.source_offset(source_address)
            .and_then(|offset| self.runtime_offset.checked_add(offset))
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
                SourceAddress::new(metadata.source_address()),
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
            let runtime_offset = RuntimeOffset::new(runtime_offset);
            segment_slices.push(ElfSegments::slice(
                runtime_offset.get(),
                *size,
                arena.backing(),
            ));
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

    fn remap_source_to_runtime_offset(
        &self,
        source_address: SourceAddress,
    ) -> Option<RuntimeOffset> {
        self.sections
            .iter()
            .copied()
            .find_map(|section| section.runtime_offset(source_address))
    }
}

impl MappedRuntimeMemory {
    pub(crate) fn map<M, K, Arch>(plan: &LinkPlan<K, Arch>) -> Result<Option<Self>>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
        M: Mmap,
    {
        let Some(arenas) = MappedArenaMap::map_plan::<M, _, Arch>(plan)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            arenas,
            modules: SecondaryMap::default(),
        }))
    }

    fn build_module(
        &mut self,
        id: ModuleId,
        layout: &MemoryLayoutPlan,
    ) -> Result<&RuntimeModuleMemory> {
        let runtime = RuntimeModuleMemory::build(id, layout, &self.arenas)?;
        let res = self.modules.insert(id, runtime);
        debug_assert!(
            res.is_none(),
            "module runtime memory was built more than once"
        );
        self.modules
            .get(id)
            .ok_or_else(|| {
                LinkerError::runtime_memory("section-region module runtime memory was not cached")
            })
            .map_err(Into::into)
    }

    pub(crate) fn repair_module<K, Arch>(
        &mut self,
        id: ModuleId,
        plan: &mut LinkPlan<K, Arch>,
    ) -> Result<()>
    where
        K: Clone + Ord,
        Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
        crate::elf::ElfRelType<Arch>: crate::ByteRepr,
    {
        let runtime = self.build_module(id, plan.memory_layout())?;
        let mut rewriter = RuntimeMetadataRewriter::<_, Arch>::new(id, plan, runtime);
        rewriter.rewrite()
    }

    pub(crate) fn populate<K, Arch>(&mut self, plan: &mut LinkPlan<K, Arch>) -> Result<()>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
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

pub(crate) fn build_arena_raw_dynamic<D, Tls, Arch>(
    scanned: ScannedDynamic<Arch>,
    runtime: RuntimeModuleMemory,
    init_fn: DynLifecycleHandler,
    fini_fn: DynLifecycleHandler,
    force_static_tls: bool,
) -> Result<RawDynamic<D, Arch>>
where
    D: Default + 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    let original_phdrs = scanned.phdrs().to_vec();
    let mut dynamic_ptr: Option<NonNull<ElfDyn<Arch::Layout>>> = None;
    let mut eh_frame_hdr: Option<NonNull<u8>> = None;
    let mut tls_info: Option<TlsInfo> = None;

    for phdr in &original_phdrs {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                let offset = runtime
                    .remap_source_to_runtime_offset(SourceAddress::new(phdr.p_vaddr()))
                    .ok_or_else(|| LinkerError::runtime_memory("failed to remap PT_DYNAMIC"))?;
                dynamic_ptr = Some(
                    NonNull::new(runtime.segments.get_mut_ptr(offset.get())).ok_or_else(|| {
                        LinkerError::runtime_memory("PT_DYNAMIC remapped to a null pointer")
                    })?,
                );
            }
            ElfProgramType::GNU_EH_FRAME => {
                let offset = runtime
                    .remap_source_to_runtime_offset(SourceAddress::new(phdr.p_vaddr()))
                    .ok_or_else(|| {
                        LinkerError::runtime_memory("failed to remap PT_GNU_EH_FRAME")
                    })?;
                eh_frame_hdr = Some(
                    NonNull::new(runtime.segments.get_mut_ptr(offset.get())).ok_or_else(|| {
                        LinkerError::runtime_memory("PT_GNU_EH_FRAME remapped to a null pointer")
                    })?,
                );
            }
            ElfProgramType::TLS => {
                let offset = runtime
                    .remap_source_to_runtime_offset(SourceAddress::new(phdr.p_vaddr()))
                    .ok_or_else(|| LinkerError::runtime_memory("failed to remap PT_TLS"))?;
                let image = runtime
                    .segments
                    .get_slice::<u8>(offset.get(), phdr.p_filesz());
                tls_info = Some(TlsInfo::new(phdr, image));
            }
            _ => {}
        }
    }

    let dynamic_ptr = dynamic_ptr
        .ok_or_else(|| LinkerError::runtime_memory("arena-backed module is missing PT_DYNAMIC"))?;
    let original_entry = scanned.ehdr().e_entry();
    let entry = runtime
        .remap_source_to_runtime_offset(SourceAddress::new(original_entry))
        .map(|offset| runtime.segments.base_addr().offset(offset.get()))
        .unwrap_or_else(|| runtime.segments.base_addr().offset(original_entry));
    let name = scanned.name().to_string();

    RawDynamic::from_parts::<Tls>(crate::image::RawDynamicParts {
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
        user_data: D::default(),
    })
}
