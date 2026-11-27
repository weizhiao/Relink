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
