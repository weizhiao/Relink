use super::layout::{MemoryLayoutPlan, SectionId};
use super::plan::{LinkPlan, ModuleId};
use crate::{
    LinkerError, Result,
    elf::{ElfDyn, ElfPhdrs, ElfProgramType},
    entity::SecondaryMap,
    image::{RawDynamic, ScannedDynamic},
    input::PathBuf,
    memory::{HostRegion, RegionAccess, VmAddr, VmOffset},
    observer::LoadObserver,
    os::Mmap,
    relocation::{RelocationArch, RelocationValueProvider},
    segment::ElfSegments,
    tls::{TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::ptr::NonNull;

mod arena;
mod rewrite;

use arena::MappedArenaMap;
pub(crate) use rewrite::GotPltTarget;
use rewrite::RuntimeMetadataRewriter;

pub(crate) struct RuntimeModuleMemory<R: RegionAccess = HostRegion> {
    sections: Box<[RuntimeSectionMemory]>,
    segments: ElfSegments<R>,
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

pub(crate) struct MappedRuntimeMemory<R: RegionAccess = HostRegion> {
    arenas: MappedArenaMap<R>,
    modules: SecondaryMap<ModuleId, RuntimeModuleMemory<R>>,
}

#[derive(Clone, Copy)]
struct RuntimeSectionMemory {
    section: SectionId,
    source_address: VmOffset,
    runtime_offset: RuntimeOffset,
    size: usize,
}

impl RuntimeSectionMemory {
    fn source_offset(self, source_address: VmOffset) -> Option<usize> {
        let offset = source_address
            .checked_offset_from(self.source_address)?
            .get();
        if self.size == 0 {
            return (offset == 0).then_some(0);
        }
        (offset < self.size).then_some(offset)
    }

    fn runtime_offset(self, source_address: VmOffset) -> Option<RuntimeOffset> {
        self.source_offset(source_address)
            .and_then(|offset| self.runtime_offset.checked_add(offset))
    }
}

impl<R: RegionAccess> RuntimeModuleMemory<R> {
    fn build(
        module_id: ModuleId,
        layout: &MemoryLayoutPlan,
        mapped_section_arenas: &MappedArenaMap<R>,
    ) -> Result<Self> {
        let module = layout.module(module_id);
        let region = mapped_section_arenas.region();

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
            let actual_address = arena.address(&region, placement.offset()).ok_or_else(|| {
                LinkerError::runtime_memory("arena-backed module section address overflowed")
            })?;
            placed_sections.push((
                section_id,
                VmOffset::new(metadata.source_address()),
                actual_address,
                metadata.size(),
            ));
        }

        let Some(base) = placed_sections
            .iter()
            .map(|(_, _, actual_address, _)| *actual_address)
            .min()
        else {
            return Err(LinkerError::runtime_memory(
                "arena-backed module does not own any alloc sections",
            )
            .into());
        };

        let mut mapped_ranges = Vec::with_capacity(placed_sections.len());
        let mut runtime_sections = Vec::with_capacity(placed_sections.len());

        for (section, source_address, actual_address, size) in &placed_sections {
            let runtime_offset = actual_address.checked_sub(base).ok_or_else(|| {
                LinkerError::runtime_memory("arena-backed module address precedes runtime base")
            })?;
            let runtime_offset = RuntimeOffset::new(runtime_offset);
            mapped_ranges.push((runtime_offset.get(), *size));
            runtime_sections.push(RuntimeSectionMemory {
                section: *section,
                source_address: *source_address,
                runtime_offset,
                size: *size,
            });
        }

        Ok(RuntimeModuleMemory {
            sections: runtime_sections.into_boxed_slice(),
            segments: ElfSegments::from_ranges(region, VmAddr::new(base), mapped_ranges),
        })
    }

    fn remap_source_to_runtime_offset(&self, source_address: VmOffset) -> Option<RuntimeOffset> {
        self.sections
            .iter()
            .copied()
            .find_map(|section| section.runtime_offset(source_address))
    }
}

impl<R: RegionAccess> MappedRuntimeMemory<R> {
    pub(crate) fn map<K, Arch, M>(mapper: &M, plan: &LinkPlan<K, Arch>) -> Result<Option<Self>>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
        M: Mmap<Region = R> + ?Sized,
    {
        let Some(arenas) = MappedArenaMap::map_plan(mapper, plan)? else {
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
    ) -> Result<&RuntimeModuleMemory<R>> {
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
        let mut rewriter = RuntimeMetadataRewriter::<_, Arch, R>::new(id, plan, runtime);
        rewriter.rewrite()
    }

    pub(crate) fn populate<K, Arch>(&mut self, plan: &mut LinkPlan<K, Arch>) -> Result<()>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        self.arenas.populate(plan)
    }

    pub(crate) fn protect(&self) -> Result<()> {
        self.arenas.protect()
    }

    pub(crate) fn take_module(&mut self, module_id: ModuleId) -> Result<RuntimeModuleMemory<R>> {
        self.modules
            .remove(module_id)
            .ok_or_else(|| {
                LinkerError::runtime_memory("section-region planned load is missing runtime memory")
            })
            .map_err(Into::into)
    }
}

pub(crate) fn build_arena_raw_dynamic<D, Tls, Arch, Obs, R>(
    scanned: ScannedDynamic<Arch>,
    runtime: RuntimeModuleMemory<R>,
    force_static_tls: bool,
    observer: &mut Obs,
) -> Result<RawDynamic<D, Arch, R>>
where
    D: Default + 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
    Obs: LoadObserver<D, Arch> + ?Sized,
    R: RegionAccess,
{
    let original_phdrs = scanned.phdrs().to_vec();
    let mut dynamic = None;
    let mut dynamic_addr = None;
    let mut eh_frame_hdr: Option<NonNull<u8>> = None;
    let mut tls_info: Option<TlsInfo> = None;

    for phdr in &original_phdrs {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                let offset = runtime
                    .remap_source_to_runtime_offset(phdr.p_vaddr())
                    .ok_or_else(|| LinkerError::runtime_memory("failed to remap PT_DYNAMIC"))?;
                let view = runtime
                    .segments
                    .read_view::<ElfDyn<Arch::Layout>>(VmOffset::new(offset.get()), phdr.p_filesz())
                    .ok_or_else(|| {
                        LinkerError::runtime_memory(
                            "PT_DYNAMIC is not directly readable from mapped segments",
                        )
                    })?;
                if view.is_empty() {
                    return Err(LinkerError::runtime_memory(
                        "PT_DYNAMIC is not directly readable from mapped segments",
                    )
                    .into());
                }
                dynamic_addr = Some(runtime.segments.base() + VmOffset::new(offset.get()));
                dynamic = Some(view);
            }
            ElfProgramType::GNU_EH_FRAME => {
                let offset = runtime
                    .remap_source_to_runtime_offset(phdr.p_vaddr())
                    .ok_or_else(|| {
                        LinkerError::runtime_memory("failed to remap PT_GNU_EH_FRAME")
                    })?;
                eh_frame_hdr = Some(
                    runtime
                        .segments
                        .borrowed_ptr::<u8>(VmOffset::new(offset.get()), phdr.p_filesz())
                        .ok_or_else(|| {
                            LinkerError::runtime_memory(
                                "PT_GNU_EH_FRAME is not directly readable from mapped segments",
                            )
                        })?,
                );
            }
            ElfProgramType::TLS => {
                let offset = runtime
                    .remap_source_to_runtime_offset(phdr.p_vaddr())
                    .ok_or_else(|| LinkerError::runtime_memory("failed to remap PT_TLS"))?;
                let image = runtime
                    .segments
                    .read_view::<u8>(VmOffset::new(offset.get()), phdr.p_filesz())
                    .ok_or_else(|| LinkerError::runtime_memory("PT_TLS image is malformed"))?;
                tls_info = Some(TlsInfo::new(phdr, image.as_slice()));
            }
            _ => {}
        }
    }

    let dynamic = dynamic
        .ok_or_else(|| LinkerError::runtime_memory("arena-backed module is missing PT_DYNAMIC"))?;
    let dynamic_addr = dynamic_addr
        .ok_or_else(|| LinkerError::runtime_memory("arena-backed module is missing PT_DYNAMIC"))?;
    let original_entry = scanned.ehdr().e_entry();
    let entry = runtime
        .remap_source_to_runtime_offset(VmOffset::new(original_entry))
        .map(|offset| runtime.segments.base() + VmOffset::new(offset.get()))
        .unwrap_or_else(|| runtime.segments.base() + VmOffset::new(original_entry));
    let path = PathBuf::from(scanned.path());

    RawDynamic::from_parts::<Tls, _>(
        crate::image::RawDynamicParts {
            path,
            entry,
            interp: None,
            phdrs: ElfPhdrs::Vec(original_phdrs),
            dynamic,
            dynamic_addr,
            eh_frame_hdr,
            tls_info,
            force_static_tls,
            relro: None,
            segments: runtime.segments,
            user_data: D::default(),
        },
        observer,
    )
}
