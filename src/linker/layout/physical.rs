use super::{
    arena::LayoutArenaId,
    section::{LayoutSectionArena, LayoutSectionId, ModuleLayout},
};
use alloc::{boxed::Box, vec::Vec};

/// One physically mapped slice owned by a single DSO inside a shared arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModulePhysicalSlice {
    section: LayoutSectionId,
    arena: LayoutArenaId,
    offset: usize,
    size: usize,
}

impl ModulePhysicalSlice {
    #[inline]
    const fn new(
        section: LayoutSectionId,
        arena: LayoutArenaId,
        offset: usize,
        size: usize,
    ) -> Self {
        Self {
            section,
            arena,
            offset,
            size,
        }
    }

    /// Returns the planned section hosted by this slice.
    #[inline]
    pub const fn section(self) -> LayoutSectionId {
        self.section
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

    pub(super) fn from_layout(layout: &ModuleLayout, sections: &LayoutSectionArena) -> Self {
        let slices = layout
            .alloc_sections()
            .iter()
            .filter_map(|section_id| {
                let placement = sections.placement(*section_id)?;
                Some(ModulePhysicalSlice::new(
                    *section_id,
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
