use super::super::layout::{ArenaId, Materialization, MemoryClass};
use super::super::plan::LinkPlan;
use crate::{
    LinkerError, Result,
    entity::SecondaryMap,
    os::{MapFlags, MappedRegion, Mapper, Mmap, PageSize, ProtFlags},
    relocation::RelocationArch,
    segment::ElfSegments,
};
use alloc::vec::Vec;

#[derive(Clone)]
pub(crate) struct MappedArena {
    memory_class: MemoryClass,
    base: usize,
    len: usize,
    region: MappedRegion,
}

#[derive(Clone, Default)]
pub(crate) struct MappedArenaMap {
    arenas: SecondaryMap<ArenaId, MappedArena>,
}

impl MappedArenaMap {
    pub(super) fn map_plan<K, Arch>(
        mapper: Mapper,
        plan: &LinkPlan<K, Arch>,
    ) -> Result<Option<Self>>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        if plan
            .modules_with_materialization(Materialization::SectionRegions)
            .next()
            .is_none()
        {
            return Ok(None);
        }

        let layout = plan.memory_layout();
        let mut arenas = Self::default();

        for (id, arena) in layout.arena_pairs() {
            let len = layout.usage(id).mapped_len();
            if len == 0 {
                continue;
            }

            let mapped = map_arena(
                mapper.as_ref(),
                len,
                arena.memory_class(),
                arena.page_size(),
            )?;

            let base = mapped.addr().get();
            let region = ElfSegments::create_region(mapped);
            arenas.insert(
                id,
                MappedArena::new(arena.memory_class(), base, len, region),
            );
        }

        Ok(Some(arenas))
    }

    pub(super) fn populate<K, Arch>(&mut self, plan: &mut LinkPlan<K, Arch>) -> Result<()>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
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
            arena.check_range(placement.offset(), placement.size())?;

            let bytes = data.as_ref();
            if bytes.len() != placement.size() {
                return Err(LinkerError::mapped_arena(
                    "mapped section arena size does not match its materialized section bytes",
                )
                .into());
            }

            arena.write_bytes(placement.offset(), bytes)?;
        }

        Ok(())
    }

    pub(super) fn protect(&self) -> Result<()> {
        for (_, arena) in self.iter() {
            arena.protect()?;
        }
        Ok(())
    }

    #[inline]
    fn insert(&mut self, id: ArenaId, arena: MappedArena) -> Option<MappedArena> {
        self.arenas.insert(id, arena)
    }

    #[inline]
    pub(super) fn get(&self, id: ArenaId) -> Option<&MappedArena> {
        self.arenas.get(id)
    }

    #[inline]
    fn iter(&self) -> impl Iterator<Item = (ArenaId, &MappedArena)> {
        self.arenas.iter()
    }
}

impl MappedArena {
    #[inline]
    fn new(memory_class: MemoryClass, base: usize, len: usize, region: MappedRegion) -> Self {
        Self {
            memory_class,
            base,
            len,
            region,
        }
    }

    #[inline]
    pub(super) fn address(&self, offset: usize) -> Option<usize> {
        self.base.checked_add(offset)
    }

    #[inline]
    pub(super) const fn base(&self) -> usize {
        self.base
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
    fn write_bytes(&self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.check_range(offset, bytes.len())?;
        unsafe { self.region.write_bytes(offset, bytes) };
        Ok(())
    }

    #[inline]
    pub(super) fn region(&self) -> MappedRegion {
        self.region.clone()
    }

    fn protect(&self) -> Result<()> {
        if self.len == 0 {
            return Ok(());
        }
        unsafe {
            self.region
                .mprotect(0, self.len, final_protection(self.memory_class))
        }
    }
}

fn map_arena(
    mapper: &dyn Mmap,
    len: usize,
    memory_class: MemoryClass,
    page_size: PageSize,
) -> Result<MappedRegion> {
    let prot = initial_protection(memory_class);
    let flags =
        MapFlags::MAP_PRIVATE | MapFlags::huge_page_size(page_size).unwrap_or_else(MapFlags::empty);
    let result = unsafe { mapper.mmap_anonymous(0, len, prot, flags) };

    if flags.contains(MapFlags::MAP_HUGETLB) {
        return result
            .or_else(|_| unsafe { mapper.mmap_anonymous(0, len, prot, MapFlags::MAP_PRIVATE) });
    }

    result
}

fn initial_protection(class: MemoryClass) -> ProtFlags {
    match class {
        MemoryClass::Code => ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
        MemoryClass::ReadOnlyData | MemoryClass::WritableData | MemoryClass::ThreadLocalData => {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
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
    use crate::os::DefaultMmap;
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

        let mapper = crate::os::Mapper::new(DefaultMmap::default());
        let mut mapped = MappedArenaMap::map_plan(mapper, &plan).unwrap().unwrap();
        mapped.populate(&mut plan).unwrap();

        let mapped_arena = mapped.get(arena).unwrap();
        let mut actual = [0_u8; 4];
        unsafe { mapped_arena.region.read_bytes(0, &mut actual) };
        assert_eq!(actual, [1, 2, 3, 4]);
    }
}
