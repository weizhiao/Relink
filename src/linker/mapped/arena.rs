use super::super::layout::{ArenaId, Materialization, MemoryClass};
use crate::linker::plan::LinkPlan;
use crate::{
    LinkerError, Result,
    entity::SecondaryMap,
    os::{MapFlags, Mmap, ProtFlags},
    segment::{ElfMemoryBacking, ElfSegments},
    sync::Arc,
};
use alloc::vec::Vec;

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
    pub(super) fn map_plan<M, K, D>(plan: &LinkPlan<K, D>) -> Result<Option<Self>>
    where
        K: Clone + Ord,
        D: 'static,
        M: Mmap,
    {
        let needs_section_regions = plan.group_order().iter().copied().any(|module_id| {
            plan.materialization(module_id) == Some(Materialization::SectionRegions)
        });
        if !needs_section_regions {
            return Ok(None);
        }

        let layout = plan.memory_layout();
        let mut arenas = Self::default();

        for (id, arena) in layout.arena_pairs() {
            let len = layout.usage(id).mapped_len();
            if len == 0 {
                continue;
            }

            let ptr: *mut core::ffi::c_void = unsafe {
                M::mmap_anonymous(
                    0,
                    len,
                    initial_protection(arena.memory_class()),
                    MapFlags::MAP_PRIVATE,
                )
            }?;

            let backing = ElfSegments::create_backing(ptr, len, M::munmap);
            arenas.insert(
                id,
                MappedArena::new(arena.memory_class(), ptr as usize, len, backing),
            );
        }

        Ok(Some(arenas))
    }

    pub(super) fn populate<K, D>(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()>
    where
        K: Clone + Ord,
        D: 'static,
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
    use crate::{input::ElfBinary, loader::Loader};
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
        let scanned = loader
            .scan_dylib(ElfBinary::new("arena-backed.so", bytes))
            .unwrap();
        let mut entries = BTreeMap::new();
        entries.insert("root", (scanned, Vec::<&str>::new().into_boxed_slice()));
        let mut plan = LinkPlan::new("root", Vec::from(["root"]), entries);
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
            4096,
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
