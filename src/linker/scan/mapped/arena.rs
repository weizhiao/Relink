use super::super::layout::{ArenaId, Materialization, MemoryClass};
use super::super::plan::LinkPlan;
use crate::{
    LinkerError, Result,
    entity::SecondaryMap,
    memory::{HostRegion, MappedRegion, RegionAccess, VmAddr, align_up},
    os::{Mmap, ProtFlags},
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
    pub(super) fn map_plan<K, Arch, Tls, M>(
        mapper: &M,
        plan: &LinkPlan<K, Arch, Tls>,
    ) -> Result<Option<Self>>
    where
        K: Clone + Ord,
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

        for (id, arena) in layout.arena_pairs() {
            let len = layout.usage(id).mapped_len();
            if len == 0 {
                continue;
            }

            total_len = align_up(total_len, arena.page_size().bytes());
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
                Some(VmAddr::null()),
                total_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                false,
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

    pub(super) fn populate<K, Arch, Tls>(&mut self, plan: &mut LinkPlan<K, Arch, Tls>) -> Result<()>
    where
        K: Clone + Ord,
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
        self.region_offset
            .checked_add(self.len)
            .expect("mapped section arena range overflowed")
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
        let region_offset = self.region_offset.checked_add(offset).ok_or_else(|| {
            LinkerError::mapped_arena("mapped section arena write offset overflowed")
        })?;
        unsafe { region.write_bytes(region_offset, bytes) }
    }

    fn protect<R: RegionAccess>(&self, region: &MappedRegion<R>) -> Result<()> {
        if self.len == 0 {
            return Ok(());
        }
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
    use crate::linker::session::ModulePayload;
    use crate::os::{DefaultMmap, PageSize};
    use crate::{image::ScannedElf, input::ElfBinary, loader::Loader};
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
        let mut loader = Loader::new();
        let ScannedElf::Dynamic(scanned) = loader
            .scan(ElfBinary::owned("arena-backed.so", bytes))
            .unwrap()
        else {
            panic!("generated dylib should scan as dynamic");
        };
        let mut entries = BTreeMap::new();
        entries.insert(
            "root",
            (
                ModulePayload::Dynamic(scanned),
                Vec::<&str>::new().into_boxed_slice(),
            ),
        );
        let mut plan: LinkPlan<&str> = LinkPlan::new("root", Vec::from(["root"]), entries);
        let root = plan.root_module();
        let section = plan
            .memory_layout()
            .module(root)
            .alloc_sections()
            .iter()
            .copied()
            .find(|section| plan.memory_layout().section(*section).name() == ".data")
            .unwrap();

        let arena = plan.memory_layout_mut().create_arena(ArenaDescriptor::new(
            PageSize::Base,
            MemoryClass::WritableData,
            ArenaSharing::Shared,
        ));
        assert!(plan.memory_layout_mut().assign(section, arena, 0));
        plan.set_materialization(root, Materialization::SectionRegions);

        // `DefaultMmap` is a unit struct only for some cfg-selected backends.
        #[allow(clippy::default_constructed_unit_structs)]
        let mapper = DefaultMmap::default();
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
