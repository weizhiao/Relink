use super::super::layout::{ArenaId, Materialization, MemoryClass};
use super::super::plan::LinkPlan;
use crate::{
    LinkerError, Result,
    entity::SecondaryMap,
    memory::{HostRegion, MappedRegion, RegionAccess, VmAddr, align_up},
    os::{Mmap, ProtFlags, SpaceInit, SpaceLayout},
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::vec::Vec;

pub(crate) struct MappedArena {
    memory_class: MemoryClass,
    region_offset: usize,
    len: usize,
}

pub(crate) struct MappedArenaMap<R: RegionAccess = HostRegion> {
    region: MappedRegion<R>,
    arenas: SecondaryMap<ArenaId, MappedArena>,
}

impl<R: RegionAccess> MappedArenaMap<R> {
    pub(super) fn map_plan<Arch, Tls, M>(
        mapper: &M,
        plan: &LinkPlan<Arch, Tls>,
    ) -> Result<Option<Self>>
    where
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R> + ?Sized,
    {
        if plan
            .modules_with_materialization(Materialization::SectionRegions)
            .next()
            .is_none()
        {
            return Ok(None);
        }

        let layout = plan.memory_layout();
        let mut arena_layouts = Vec::new();
        let mut total_len = 0usize;
        let page_size = mapper.page_size().bytes();
        let mut align = page_size;

        for (id, arena) in layout.arena_pairs() {
            let len = layout.usage(id).mapped_len();
            if len == 0 {
                continue;
            }

            let arena_page_size = arena.page_size().bytes();
            if !arena_page_size.is_power_of_two() || arena_page_size < page_size {
                return Err(LinkerError::mapped_arena(
                    "arena page size must be a power of two at least as large as the backend page size",
                )
                .into());
            }
            align = align.max(arena_page_size);
            total_len = align_up(total_len, arena_page_size);
            let region_offset = total_len;
            total_len = total_len.checked_add(len).ok_or_else(|| {
                LinkerError::mapped_arena("mapped section arena allocation length overflowed")
            })?;
            arena_layouts.push((id, arena.memory_class(), region_offset, len));
        }

        if total_len == 0 {
            return Err(LinkerError::mapped_arena(
                "section-region planned load does not contain mapped arena bytes",
            )
            .into());
        }

        let region = unsafe {
            mapper.create_space(
                SpaceLayout {
                    addr: Some(VmAddr::null()),
                    len: total_len,
                    align,
                    offset: 0,
                },
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                SpaceInit::Zeroed,
            )
        }?;
        let mut arenas = Self {
            region,
            arenas: SecondaryMap::default(),
        };

        for (id, memory_class, region_offset, len) in arena_layouts {
            arenas.arenas.insert(
                id,
                MappedArena {
                    memory_class,
                    region_offset,
                    len,
                },
            );
        }

        Ok(Some(arenas))
    }

    pub(super) fn populate<Arch, Tls>(&mut self, plan: &mut LinkPlan<Arch, Tls>) -> Result<()>
    where
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
    {
        let placed_sections = plan
            .memory_layout()
            .section_placements()
            .collect::<Vec<_>>();

        for (section_id, placement) in placed_sections {
            let data = plan.section_data(section_id)?;
            let arena = self.get(placement.arena()).ok_or_else(|| {
                LinkerError::mapped_arena("mapped section arenas referenced a missing arena")
            })?;

            let bytes = data.as_ref();
            if bytes.len() != placement.size() {
                return Err(LinkerError::mapped_arena(
                    "mapped section arena size does not match its materialized section bytes",
                )
                .into());
            }

            arena.write_bytes(&self.region, placement.offset(), bytes)?;
        }

        Ok(())
    }

    pub(super) fn protect(&self) -> Result<()> {
        let mut arenas = self.arenas.iter().collect::<Vec<_>>();
        arenas.sort_by_key(|(_, arena)| arena.region_offset);

        let mut cursor = 0usize;
        for (_, arena) in arenas {
            if cursor < arena.region_offset {
                unsafe {
                    self.region.mprotect(
                        cursor,
                        arena.region_offset - cursor,
                        ProtFlags::PROT_NONE,
                    )?;
                }
            }
            arena.protect(&self.region)?;
            cursor = arena.end();
        }

        if cursor < self.region.len() {
            unsafe {
                self.region
                    .mprotect(cursor, self.region.len() - cursor, ProtFlags::PROT_NONE)?;
            }
        }
        Ok(())
    }

    #[inline]
    pub(super) fn get(&self, id: ArenaId) -> Option<&MappedArena> {
        self.arenas.get(id)
    }

    #[inline]
    pub(super) fn region(&self) -> MappedRegion<R> {
        self.region.clone()
    }
}

impl MappedArena {
    #[inline]
    pub(super) fn address<R: RegionAccess>(
        &self,
        region: &MappedRegion<R>,
        offset: usize,
    ) -> Option<usize> {
        region
            .addr()
            .get()
            .checked_add(self.region_offset)?
            .checked_add(offset)
    }

    #[inline]
    fn end(&self) -> usize {
        self.region_offset + self.len
    }

    #[inline]
    fn check_range(&self, offset: usize, len: usize) -> Result<()> {
        let end = offset.checked_add(len).ok_or_else(|| {
            LinkerError::mapped_arena(
                "mapped section arena placement exceeds the allocated arena bounds",
            )
        })?;
        if end > self.len {
            return Err(LinkerError::mapped_arena(
                "mapped section arena placement exceeds the allocated arena bounds",
            )
            .into());
        }
        Ok(())
    }

    #[inline]
    fn write_bytes<R: RegionAccess>(
        &self,
        region: &MappedRegion<R>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<()> {
        self.check_range(offset, bytes.len())?;
        let region_offset = self.region_offset + offset;
        unsafe { region.write_bytes(region_offset, bytes) }
    }

    fn protect<R: RegionAccess>(&self, region: &MappedRegion<R>) -> Result<()> {
        unsafe {
            region.mprotect(
                self.region_offset,
                self.len,
                final_protection(self.memory_class),
            )
        }
    }
}

fn final_protection(class: MemoryClass) -> ProtFlags {
    match class {
        MemoryClass::Code => ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        MemoryClass::ReadOnlyData => ProtFlags::PROT_READ,
        MemoryClass::WritableData | MemoryClass::ThreadLocalData => {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{ArenaDescriptor, ArenaSharing, LinkPlan};
    use super::*;
    use crate::arch::NativeArch;
    use crate::os::{AllocMmap, PageSize};
    use crate::runtime::{AddressSpaceId, Domain};
    use crate::{
        image::{ScannedElf, SyntheticModule},
        input::ElfBinary,
        linker::{GraphModule, LinkContext, ModuleKey},
        loader::Loader,
    };
    use alloc::{collections::BTreeMap, vec::Vec};
    use gen_elf::{Arch, DylibWriter, ElfWriterConfig, SymbolDesc};

    #[test]
    fn populate_mapped_arenas_materializes_and_copies_section_data() {
        let output = DylibWriter::with_config(
            Arch::current(),
            ElfWriterConfig::default().with_bind_now(true),
        )
        .write(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])])
        .unwrap();
        let bytes = output.data;
        let loader = Loader::new();
        let ScannedElf::Dynamic(scanned) = loader
            .scan(ElfBinary::owned("arena-backed.so", bytes))
            .unwrap()
        else {
            panic!("generated dylib should scan as dynamic");
        };
        let mut entries = BTreeMap::new();
        let mut context = LinkContext::<()>::new(Domain::native(AddressSpaceId::PROCESS));
        let root = context
            .insert(GraphModule::new(
                "root",
                SyntheticModule::empty(
                    &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
                    "root",
                ),
            ))
            .unwrap();
        let root_slot = context.committed.module_slot(root.id()).unwrap();
        entries.insert(
            root_slot,
            (
                ModuleKey::from("root"),
                scanned,
                Vec::new().into_boxed_slice(),
            ),
        );
        let mut plan: LinkPlan = LinkPlan::new(root_slot, Vec::from([root_slot]), entries);
        let root = plan.root_module();
        let section = plan
            .memory_layout()
            .module(root)
            .alloc_sections()
            .iter()
            .copied()
            .find(|section| plan.memory_layout().section(*section).name() == b".data")
            .unwrap();

        let mapper = AllocMmap::new();
        plan.set_materialization(root, Materialization::SectionRegions);
        // Planning can use custom page sizes; mapping must reject sizes that
        // cannot preserve the backend's allocation and protection boundaries.
        for page_size in [
            PageSize::new(mapper.page_size().bytes() / 2).unwrap(),
            PageSize::Custom(core::num::NonZeroUsize::new(3 * PageSize::BASE_BYTES).unwrap()),
        ] {
            let arena = plan.memory_layout_mut().create_arena(ArenaDescriptor::new(
                page_size,
                MemoryClass::WritableData,
                ArenaSharing::Shared,
            ));
            assert!(plan.memory_layout_mut().assign(section, arena, 0));
            assert!(MappedArenaMap::map_plan(&mapper, &plan).is_err());
        }

        let arena = plan.memory_layout_mut().create_arena(ArenaDescriptor::new(
            PageSize::Base,
            MemoryClass::WritableData,
            ArenaSharing::Shared,
        ));
        assert!(plan.memory_layout_mut().assign(section, arena, 0));
        let mut mapped = MappedArenaMap::map_plan(&mapper, &plan).unwrap().unwrap();
        mapped.populate(&mut plan).unwrap();

        let mapped_arena = mapped.get(arena).unwrap();
        let region = mapped.region();
        let mut actual = [0_u8; 4];
        unsafe {
            region
                .read_bytes(mapped_arena.region_offset, &mut actual)
                .unwrap()
        };
        assert_eq!(actual, [1, 2, 3, 4]);
    }
}
