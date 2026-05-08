use super::super::layout::{ArenaId, Materialization, MemoryClass};
use crate::linker::plan::LinkPlan;
use crate::{
    LinkerError, Result,
    entity::SecondaryMap,
    os::{MapFlags, Mmap, PageSize, ProtFlags},
    relocation::RelocationArch,
    segment::{ElfMemoryBacking, ElfSegments},
    sync::Arc,
};
use alloc::vec::Vec;
use core::ffi::c_void;

#[derive(Clone)]
pub(crate) struct MappedArena {
    memory_class: MemoryClass,
    base: usize,
    len: usize,
    backing: Arc<ElfMemoryBacking>,
}

#[derive(Clone, Default)]
pub(crate) struct MappedArenaMap {
    arenas: SecondaryMap<ArenaId, MappedArena>,
}

impl MappedArenaMap {
    pub(super) fn map_plan<M, K, Arch>(plan: &LinkPlan<K, Arch>) -> Result<Option<Self>>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
        M: Mmap,
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

            let ptr = map_arena::<M>(len, arena.memory_class(), arena.page_size())?;

            let backing = ElfSegments::create_backing(ptr, len, M::munmap);
            arenas.insert(
                id,
                MappedArena::new(arena.memory_class(), ptr as usize, len, backing),
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
            let arena = self.get_mut(placement.arena()).ok_or_else(|| {
                LinkerError::mapped_arena("mapped section arenas referenced a missing arena")
            })?;
            let dst = arena
                .slice_mut(placement.offset(), placement.size())
                .ok_or_else(|| {
                    LinkerError::mapped_arena(
                        "mapped section arena placement exceeds the allocated arena bounds",
                    )
                })?;

            let bytes = data.as_ref();
            if bytes.len() != dst.len() {
                return Err(LinkerError::mapped_arena(
                    "mapped section arena size does not match its materialized section bytes",
                )
                .into());
            }

            dst.copy_from_slice(bytes);
        }

        Ok(())
    }

    pub(super) fn protect<M>(&self) -> Result<()>
    where
        M: Mmap,
    {
        for (_, arena) in self.iter() {
            arena.protect::<M>()?;
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
    pub(super) fn get_mut(&mut self, id: ArenaId) -> Option<&mut MappedArena> {
        self.arenas.get_mut(id)
    }

    #[inline]
    fn iter(&self) -> impl Iterator<Item = (ArenaId, &MappedArena)> {
        self.arenas.iter()
    }
}

impl MappedArena {
    #[inline]
    fn new(
        memory_class: MemoryClass,
        base: usize,
        len: usize,
        backing: Arc<ElfMemoryBacking>,
    ) -> Self {
        Self {
            memory_class,
            base,
            len,
            backing,
        }
    }

    #[inline]
    pub(super) fn address(&self, offset: usize) -> Option<usize> {
        self.base.checked_add(offset)
    }

    #[inline]
    pub(super) fn backing(&self) -> Arc<ElfMemoryBacking> {
        Arc::clone(&self.backing)
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.len) }
    }

    #[inline]
    fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        self.bytes_mut().get_mut(offset..end)
    }

    fn protect<M: Mmap>(&self) -> Result<()> {
        if self.len == 0 {
            return Ok(());
        }
        unsafe {
            M::mprotect(
                self.base as *mut _,
                self.len,
                final_protection(self.memory_class),
            )
        }
    }
}

fn map_arena<M>(len: usize, memory_class: MemoryClass, page_size: PageSize) -> Result<*mut c_void>
where
    M: Mmap,
{
    let prot = initial_protection(memory_class);
    let flags =
        MapFlags::MAP_PRIVATE | MapFlags::huge_page_size(page_size).unwrap_or_else(MapFlags::empty);
    let result = unsafe { M::mmap_anonymous(0, len, prot, flags) };

    if flags.contains(MapFlags::MAP_HUGETLB) {
        return result
            .or_else(|_| unsafe { M::mmap_anonymous(0, len, prot, MapFlags::MAP_PRIVATE) });
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
    use super::super::super::layout::{Arena, ArenaSharing};
    use super::super::super::plan::LinkPlan;
    use super::*;
    use crate::os::DefaultMmap;
    use crate::{image::ScannedElf, input::ElfBinary, loader::Loader};
    use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
    use gen_elf::{Arch, DylibWriter, ElfWriterConfig, SymbolDesc};

    #[test]
    fn populate_mapped_arenas_materializes_and_copies_section_data() {
        let output = DylibWriter::with_config(
            Arch::current(),
            ElfWriterConfig::default().with_bind_now(true),
        )
        .write(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])])
        .unwrap();
        let bytes: &'static [u8] = Box::leak(output.data.into_boxed_slice());
        let mut loader = Loader::new();
        let ScannedElf::Dynamic(scanned) = loader
            .scan(ElfBinary::new("arena-backed.so", bytes))
            .unwrap()
        else {
            panic!("generated dylib should scan as dynamic");
        };
        let mut entries = BTreeMap::new();
        entries.insert("root", (scanned, Vec::<&str>::new().into_boxed_slice()));
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

        let arena = plan.memory_layout_mut().create_arena(Arena::new(
            PageSize::Base,
            MemoryClass::WritableData,
            ArenaSharing::Shared,
        ));
        assert!(plan.memory_layout_mut().assign(section, arena, 0));
        plan.set_materialization(root, Materialization::SectionRegions);

        let mut mapped = MappedArenaMap::map_plan::<DefaultMmap, _, _>(&plan)
            .unwrap()
            .unwrap();
        mapped.populate(&mut plan).unwrap();

        let mapped_arena = mapped.get_mut(arena).unwrap();
        assert_eq!(&mapped_arena.bytes_mut()[0..4], [1_u8, 2, 3, 4].as_slice());
    }
}
