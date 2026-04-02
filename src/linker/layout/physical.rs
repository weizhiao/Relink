use super::{
    arena::{LayoutArena, LayoutArenaId},
    region::{LayoutRegionArena, LayoutRegionId},
    section::{LayoutSectionMetadataArena, ModuleLayout},
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// One physically mapped slice owned by a single DSO inside a shared arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModulePhysicalSlice {
    region: LayoutRegionId,
    arena: LayoutArenaId,
    offset: usize,
    size: usize,
}

impl ModulePhysicalSlice {
    #[inline]
    const fn new(region: LayoutRegionId, arena: LayoutArenaId, offset: usize, size: usize) -> Self {
        Self {
            region,
            arena,
            offset,
            size,
        }
    }

    /// Returns the logical region that owns this slice.
    #[inline]
    pub const fn region(self) -> LayoutRegionId {
        self.region
    }

    /// Returns the physical arena that hosts this slice.
    #[inline]
    pub const fn arena(self) -> LayoutArenaId {
        self.arena
    }

    /// Returns the byte offset inside the arena.
    #[inline]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Returns the byte length of the slice.
    #[inline]
    pub const fn size(self) -> usize {
        self.size
    }
}

/// The physically mapped slices owned by one DSO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModulePhysicalLayout {
    slices: Box<[ModulePhysicalSlice]>,
}

impl ModulePhysicalLayout {
    /// Creates an empty physical DSO layout.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn from_layout<K>(
        key: &K,
        layout: &ModuleLayout,
        section_metadata: &LayoutSectionMetadataArena,
        regions: &LayoutRegionArena,
        region_owners: &BTreeMap<LayoutRegionId, K>,
    ) -> Self
    where
        K: Ord,
    {
        let mut region_ids = Vec::<LayoutRegionId>::new();

        for (_, section_id) in layout.section_entries() {
            let Some(region_id) = section_metadata
                .get(*section_id)
                .and_then(|section| section.region())
                .map(|region| region.region())
            else {
                continue;
            };

            if region_owners.get(&region_id) != Some(key) {
                continue;
            }

            if !region_ids.iter().any(|existing| *existing == region_id) {
                region_ids.push(region_id);
            }
        }

        let slices = region_ids
            .into_iter()
            .filter_map(|region_id| {
                let placement = regions.get(region_id)?.placement()?;
                Some(ModulePhysicalSlice::new(
                    region_id,
                    placement.arena(),
                    placement.offset(),
                    placement.size(),
                ))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self { slices }
    }

    /// Returns every physical slice owned by the DSO.
    #[inline]
    pub fn slices(&self) -> &[ModulePhysicalSlice] {
        &self.slices
    }

    /// Iterates over the distinct physical arenas touched by the DSO.
    pub fn arenas(&self) -> impl Iterator<Item = LayoutArenaId> + '_ {
        let mut arenas = Vec::new();
        for slice in self.slices.iter().copied() {
            if !arenas.iter().any(|arena| *arena == slice.arena()) {
                arenas.push(slice.arena());
            }
        }
        arenas.into_iter()
    }

    /// Returns the slices owned by the DSO inside one arena.
    pub fn slices_in_arena(
        &self,
        arena: LayoutArenaId,
    ) -> impl Iterator<Item = ModulePhysicalSlice> + '_ {
        self.slices
            .iter()
            .copied()
            .filter(move |slice| slice.arena() == arena)
    }

    /// Returns whether the DSO has any bytes mapped inside `arena`.
    #[inline]
    pub fn touches_arena(&self, arena: LayoutArenaId) -> bool {
        self.slices.iter().any(|slice| slice.arena() == arena)
    }
}

/// The physically mapped DSO layouts derived for one memory-layout plan.
#[derive(Debug, Clone)]
pub struct LayoutPhysicalPlan<K> {
    modules: BTreeMap<K, ModulePhysicalLayout>,
}

impl<K> Default for LayoutPhysicalPlan<K> {
    #[inline]
    fn default() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }
}

impl<K> LayoutPhysicalPlan<K>
where
    K: Ord,
{
    /// Creates an empty physical-layout index.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the physical layout for one module.
    #[inline]
    pub fn module(&self, key: &K) -> Option<&ModulePhysicalLayout> {
        self.modules.get(key)
    }

    /// Iterates over the physical layout of every module.
    #[inline]
    pub fn modules(&self) -> impl Iterator<Item = (&K, &ModulePhysicalLayout)> {
        self.modules.iter()
    }

    /// Inserts or replaces the physical layout for one module.
    #[inline]
    pub fn insert_module(
        &mut self,
        key: K,
        layout: ModulePhysicalLayout,
    ) -> Option<ModulePhysicalLayout> {
        self.modules.insert(key, layout)
    }

    /// Returns whether `arena` currently hosts any bytes from `key`.
    #[inline]
    pub fn touches_arena(&self, key: &K, arena: LayoutArenaId) -> bool {
        self.module(key)
            .is_some_and(|layout| layout.touches_arena(arena))
    }

    /// Iterates over modules that currently own bytes inside `arena`.
    pub fn modules_in_arena(
        &self,
        arena: LayoutArenaId,
    ) -> impl Iterator<Item = (&K, &ModulePhysicalLayout)> {
        self.modules
            .iter()
            .filter(move |(_, layout)| layout.touches_arena(arena))
    }
}

/// One materialized physical arena buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutArenaImage {
    arena: LayoutArena,
    bytes: Box<[u8]>,
}

impl LayoutArenaImage {
    #[inline]
    pub(crate) fn new(arena: LayoutArena, bytes: Box<[u8]>) -> Self {
        Self { arena, bytes }
    }

    /// Returns the arena descriptor.
    #[inline]
    pub const fn arena(&self) -> LayoutArena {
        self.arena
    }

    /// Returns the materialized bytes for this arena.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Returns the allocated byte length of the arena image.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the arena image is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A materialized physical image derived from one memory-layout plan.
#[derive(Debug, Clone)]
pub struct LayoutPhysicalImage<K> {
    arenas: BTreeMap<LayoutArenaId, LayoutArenaImage>,
    modules: BTreeMap<K, ModulePhysicalLayout>,
}

impl<K> Default for LayoutPhysicalImage<K> {
    #[inline]
    fn default() -> Self {
        Self {
            arenas: BTreeMap::new(),
            modules: BTreeMap::new(),
        }
    }
}

impl<K> LayoutPhysicalImage<K>
where
    K: Ord,
{
    /// Creates an empty physical image.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns one materialized arena image.
    #[inline]
    pub fn arena(&self, id: LayoutArenaId) -> Option<&LayoutArenaImage> {
        self.arenas.get(&id)
    }

    /// Returns the bytes for one materialized arena image.
    #[inline]
    pub fn arena_bytes(&self, id: LayoutArenaId) -> Option<&[u8]> {
        self.arena(id).map(LayoutArenaImage::bytes)
    }

    /// Iterates over every materialized arena image.
    #[inline]
    pub fn arena_entries(&self) -> impl Iterator<Item = (LayoutArenaId, &LayoutArenaImage)> {
        self.arenas.iter().map(|(id, image)| (*id, image))
    }

    /// Returns the physical layout for one module.
    #[inline]
    pub fn module(&self, key: &K) -> Option<&ModulePhysicalLayout> {
        self.modules.get(key)
    }

    /// Returns the bytes covered by one physical slice.
    #[inline]
    pub fn slice_bytes(&self, slice: ModulePhysicalSlice) -> Option<&[u8]> {
        let arena = self.arena(slice.arena())?;
        let end = slice.offset().checked_add(slice.size())?;
        arena.bytes().get(slice.offset()..end)
    }

    #[inline]
    pub(crate) fn arena_bytes_mut(&mut self, id: LayoutArenaId) -> Option<&mut [u8]> {
        self.arenas.get_mut(&id).map(LayoutArenaImage::bytes_mut)
    }

    #[inline]
    pub(crate) fn insert_arena(&mut self, id: LayoutArenaId, arena: LayoutArena, len: usize) {
        self.arenas.insert(
            id,
            LayoutArenaImage::new(arena, alloc::vec![0; len].into_boxed_slice()),
        );
    }

    #[inline]
    pub(crate) fn insert_module(&mut self, key: K, layout: ModulePhysicalLayout) {
        self.modules.insert(key, layout);
    }
}
