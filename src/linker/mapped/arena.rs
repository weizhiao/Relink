use super::super::layout::{
    LayoutArenaId, LayoutMemoryClass, LayoutModuleMaterialization, LayoutSectionData,
};
use crate::linker::plan::LinkPlan;
use crate::{
    Result,
    os::{MapFlags, Mmap, ProtFlags},
    segment::{ElfMemoryBacking, ElfSegments},
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

#[derive(Clone)]
pub(crate) struct MappedArena {
    memory_class: LayoutMemoryClass,
    base: usize,
    len: usize,
    backing: Arc<ElfMemoryBacking>,
}

pub(crate) type MappedArenaMap = BTreeMap<LayoutArenaId, MappedArena>;

impl MappedArena {
    #[inline]
    fn new(
        memory_class: LayoutMemoryClass,
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

pub(crate) fn map_planned_section_arenas<M, K, D>(
    plan: &LinkPlan<K, D>,
) -> Result<Option<MappedArenaMap>>
where
    K: Clone + Ord,
    D: 'static,
    M: Mmap,
{
    let needs_section_regions = plan.group_order_ids().iter().copied().any(|module_id| {
        plan.module_materialization(module_id) == Some(LayoutModuleMaterialization::SectionRegions)
    });
    if !needs_section_regions {
        return Ok(None);
    }

    let layout = plan.memory_layout();
    if !layout.has_section_placements() {
        return Ok(None);
    }

    let mut arenas = BTreeMap::new();

    for (id, arena) in layout.arena_entries() {
        let len = layout.arena_usage(id).mapped_len();
        if len == 0 {
            continue;
        }

        let ptr = unsafe {
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

pub(crate) fn populate_mapped_arenas<K, D>(
    plan: &mut LinkPlan<K, D>,
    arenas: &mut MappedArenaMap,
) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let placed_sections = plan
        .memory_layout()
        .sections()
        .iter_records()
        .filter_map(|(section_id, record)| {
            let placement = record.placement()?;
            Some((section_id, placement, record.metadata().zero_fill()))
        })
        .collect::<Vec<_>>();

    for (section_id, placement, zero_fill) in placed_sections {
        let data = plan.section_data(section_id)?;
        let arena = arenas.get_mut(&placement.arena()).ok_or_else(|| {
            crate::custom_error("mapped section arenas referenced a missing arena")
        })?;
        let dst = arena
            .slice_mut(placement.offset(), placement.size())
            .ok_or_else(|| {
                crate::custom_error(
                    "mapped section arena placement exceeds the allocated arena bounds",
                )
            })?;

        if let Some(data) = data {
            copy_section_data(data, dst)?;
            continue;
        }

        if zero_fill {
            continue;
        }

        return Err(crate::custom_error(
            "mapped section arenas are missing materialized section data",
        ));
    }

    Ok(())
}

fn copy_section_data(data: &LayoutSectionData, dst: &mut [u8]) -> Result<()> {
    match data {
        LayoutSectionData::Bytes(bytes) => copy_section_bytes(bytes.as_ref(), dst),
        LayoutSectionData::ZeroFill { size } => {
            if *size != dst.len() {
                return Err(crate::custom_error(
                    "mapped section arena zero-fill size does not match its placement",
                ));
            }
            Ok(())
        }
    }
}

fn copy_section_bytes(bytes: &[u8], dst: &mut [u8]) -> Result<()> {
    if bytes.len() != dst.len() {
        return Err(crate::custom_error(
            "mapped section arena size does not match its materialized section bytes",
        ));
    }

    dst.copy_from_slice(bytes);
    Ok(())
}

pub(crate) fn protect_mapped_arenas<M>(arenas: &MappedArenaMap) -> Result<()>
where
    M: Mmap,
{
    for arena in arenas.values() {
        arena.protect::<M>()?;
    }
    Ok(())
}

fn initial_protection(class: LayoutMemoryClass) -> ProtFlags {
    match class {
        LayoutMemoryClass::Code => {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC
        }
        LayoutMemoryClass::ReadOnlyData
        | LayoutMemoryClass::WritableData
        | LayoutMemoryClass::ThreadLocalData => ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
    }
}

fn final_protection(class: LayoutMemoryClass) -> ProtFlags {
    match class {
        LayoutMemoryClass::Code => ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        LayoutMemoryClass::ReadOnlyData => ProtFlags::PROT_READ,
        LayoutMemoryClass::WritableData | LayoutMemoryClass::ThreadLocalData => {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::layout::{LayoutArena, LayoutArenaSharing};
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
            .unwrap()
            .alloc_sections()
            .iter()
            .copied()
            .find(|section| plan.memory_layout().section_metadata(*section).name() == ".data")
            .unwrap();

        let arena = plan.memory_layout_mut().create_arena(LayoutArena::new(
            4096,
            LayoutMemoryClass::WritableData,
            LayoutArenaSharing::Shared,
        ));
        assert!(
            plan.memory_layout_mut()
                .assign_section_to_arena(section, arena, 0)
        );
        plan.set_module_materialization(root, LayoutModuleMaterialization::SectionRegions);

        let mut mapped = map_planned_section_arenas::<DefaultMmap, _, _>(&plan)
            .unwrap()
            .unwrap();
        populate_mapped_arenas(&mut plan, &mut mapped).unwrap();

        let mapped_arena = mapped.get_mut(&arena).unwrap();
        assert_eq!(&mapped_arena.bytes_mut()[0..4], [1_u8, 2, 3, 4].as_slice());
    }
}
