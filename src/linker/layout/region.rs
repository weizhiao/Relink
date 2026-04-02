use super::{
    address::LayoutAddress,
    arena::{LayoutArenaId, LayoutMemoryClass},
    section::LayoutSectionId,
};
use crate::entity::{EntityArena, entity_ref};
use alloc::vec::Vec;

/// A stable id for one logical layout region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutRegionId(usize);
entity_ref!(LayoutRegionId);

/// The assignment of one section inside a logical region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionRegionPlacement {
    region: LayoutRegionId,
    offset: usize,
    size: usize,
}

impl SectionRegionPlacement {
    /// Creates a new section-to-region placement.
    #[inline]
    pub const fn new(region: LayoutRegionId, offset: usize, size: usize) -> Self {
        Self {
            region,
            offset,
            size,
        }
    }

    /// Returns the logical region that owns the section.
    #[inline]
    pub const fn region(self) -> LayoutRegionId {
        self.region
    }

    /// Returns the byte offset inside the logical region.
    #[inline]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Returns the logical size of the section.
    #[inline]
    pub const fn size(self) -> usize {
        self.size
    }
}

/// The placement of one logical region inside a physical arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutRegionPlacement {
    arena: LayoutArenaId,
    offset: usize,
    size: usize,
}

impl LayoutRegionPlacement {
    /// Creates a new region-to-arena placement.
    #[inline]
    pub const fn new(arena: LayoutArenaId, offset: usize, size: usize) -> Self {
        Self {
            arena,
            offset,
            size,
        }
    }

    /// Returns the physical arena that hosts the region.
    #[inline]
    pub const fn arena(self) -> LayoutArenaId {
        self.arena
    }

    /// Returns the byte offset inside the physical arena.
    #[inline]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Returns the logical size of the region.
    #[inline]
    pub const fn size(self) -> usize {
        self.size
    }

    /// Returns the start address of the region.
    #[inline]
    pub const fn address(self) -> LayoutAddress {
        LayoutAddress::new(self.arena, self.offset)
    }
}

/// One logical region that groups sections before physical mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutRegion {
    memory_class: LayoutMemoryClass,
    alignment: usize,
    size: usize,
    sections: Vec<LayoutSectionId>,
    placement: Option<LayoutRegionPlacement>,
}

impl LayoutRegion {
    /// Creates an empty logical region for one memory class.
    #[inline]
    pub fn new(memory_class: LayoutMemoryClass) -> Self {
        Self {
            memory_class,
            alignment: 1,
            size: 0,
            sections: Vec::new(),
            placement: None,
        }
    }

    /// Returns the memory class hosted by the region.
    #[inline]
    pub const fn memory_class(&self) -> LayoutMemoryClass {
        self.memory_class
    }

    /// Returns the maximum alignment required by attached sections.
    #[inline]
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Returns the logical size of the region in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the section ids attached to the region.
    #[inline]
    pub fn sections(&self) -> &[LayoutSectionId] {
        &self.sections
    }

    /// Returns the physical placement of the region, when assigned.
    #[inline]
    pub const fn placement(&self) -> Option<LayoutRegionPlacement> {
        self.placement
    }

    #[inline]
    pub(super) fn rebuild_shape(
        &mut self,
        sections: Vec<LayoutSectionId>,
        alignment: usize,
        size: usize,
    ) {
        self.sections = sections;
        self.alignment = alignment.max(1);
        self.size = size;
    }

    #[inline]
    pub(super) fn set_placement(&mut self, placement: LayoutRegionPlacement) {
        self.placement = Some(placement);
    }

    #[inline]
    pub(super) fn clear_placement(&mut self) -> Option<LayoutRegionPlacement> {
        self.placement.take()
    }
}

/// A dense arena of logical layout regions.
#[derive(Debug, Clone, Default)]
pub struct LayoutRegionArena {
    regions: EntityArena<LayoutRegionId, LayoutRegion>,
}

impl LayoutRegionArena {
    /// Creates an empty region arena.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new logical region and returns its region id.
    #[inline]
    pub fn insert(&mut self, region: LayoutRegion) -> LayoutRegionId {
        self.regions.push(region)
    }

    /// Returns one logical region by region id.
    #[inline]
    pub fn get(&self, id: LayoutRegionId) -> Option<&LayoutRegion> {
        self.regions.get(id)
    }

    /// Returns one logical region by region id mutably.
    #[inline]
    pub fn get_mut(&mut self, id: LayoutRegionId) -> Option<&mut LayoutRegion> {
        self.regions.get_mut(id)
    }

    /// Iterates over every logical region together with its region id.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (LayoutRegionId, &LayoutRegion)> {
        self.regions.iter()
    }

    /// Iterates over every logical region mutably together with its region id.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (LayoutRegionId, &mut LayoutRegion)> {
        self.regions.iter_mut()
    }
}
