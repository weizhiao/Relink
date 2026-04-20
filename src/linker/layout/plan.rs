use super::{
    arena::{Arena, ArenaId, ArenaUsage},
    section::{LayoutSectionArena, ModuleLayout, SectionId, SectionMetadata, SectionPlacement},
};
use crate::{
    entity::{PrimaryMap, SecondaryMap},
    image::{ModuleCapability, ScannedDylib, ScannedSectionId},
    linker::plan::ModuleId,
};

/// The requested materialization mode for one module during planned load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Materialization {
    /// Materialize the full DSO into a private region with multiple
    /// permission-specific mapped areas derived from `PT_LOAD`.
    WholeDsoRegion,
    /// Materialize alloc sections directly into section regions / arenas.
    SectionRegions,
}

impl Materialization {
    pub(crate) const fn default(capability: ModuleCapability) -> Self {
        if capability.supports_reorder_repair() {
            Self::SectionRegions
        } else {
            Self::WholeDsoRegion
        }
    }
}

/// A memory-layout core derived from a logical [`super::super::LinkPlan`].
///
/// The logical module graph remains authoritative for dependency resolution and
/// symbol-lookup scope. This type owns section metadata/data together with the
/// physical arena placements selected by planning passes.
#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryLayoutPlan {
    arenas: PrimaryMap<ArenaId, Arena>,
    modules: SecondaryMap<ModuleId, ModuleLayout>,
    materialization: SecondaryMap<ModuleId, Materialization>,
    sections: LayoutSectionArena,
}

impl MemoryLayoutPlan {
    /// Returns the planned physical arenas for the current load session.
    #[inline]
    pub fn arenas(&self) -> &[Arena] {
        self.arenas.as_slice()
    }

    /// Iterates over planned arenas together with their stable arena ids.
    #[inline]
    pub fn arena_pairs(&self) -> impl Iterator<Item = (ArenaId, &Arena)> {
        self.arenas.iter()
    }

    /// Returns one arena descriptor by arena id.
    #[inline]
    pub fn arena(&self, id: ArenaId) -> &Arena {
        self.arenas
            .get(id)
            .expect("layout plan referenced missing arena")
    }

    /// Returns the planned layout for one module.
    #[inline]
    pub fn module(&self, module_id: ModuleId) -> &ModuleLayout {
        self.modules
            .get(module_id)
            .expect("layout plan referenced missing module layout")
    }

    /// Iterates over all planned module layouts.
    #[inline]
    pub fn modules(&self) -> impl Iterator<Item = (ModuleId, &ModuleLayout)> {
        self.modules.iter()
    }

    /// Returns the currently configured materialization mode for one module.
    #[inline]
    pub fn materialization(&self, module_id: ModuleId) -> Option<Materialization> {
        self.materialization.get(module_id).copied()
    }

    /// Updates the planned materialization mode for one module.
    #[inline]
    pub fn set_materialization(
        &mut self,
        module_id: ModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.materialization.insert(module_id, mode)
    }

    /// Returns the arena that owns all section records.
    #[inline]
    pub fn sections(&self) -> impl Iterator<Item = (SectionId, &SectionMetadata)> {
        self.sections.iter()
    }

    /// Returns one section metadata record by internal section id.
    #[inline]
    pub fn section(&self, id: SectionId) -> &SectionMetadata {
        self.sections
            .get(id)
            .expect("layout plan referenced missing section metadata")
    }

    /// Returns one section's materialized data, when present.
    #[inline]
    pub fn data(&self, section: SectionId) -> Option<&crate::AlignedBytes> {
        self.sections.data(section)
    }

    #[inline]
    pub(crate) fn data_mut(
        &mut self,
        section: SectionId,
    ) -> Option<&mut crate::AlignedBytes> {
        self.sections.data_mut(section)
    }

    #[inline]
    pub(crate) fn install_section_data(
        &mut self,
        section: SectionId,
        bytes: impl Into<crate::AlignedBytes>,
    ) {
        self.sections.install_scanned_data(section, bytes);
    }

    #[inline]
    pub(crate) fn mark_section_data_override(&mut self, section: SectionId) -> Option<()> {
        self.sections.mark_data_override(section)
    }

    #[inline]
    pub(crate) fn with_disjoint_section_data_mut<R>(
        &mut self,
        read_a: SectionId,
        read_b: SectionId,
        write: SectionId,
        f: impl FnOnce(&crate::AlignedBytes, &crate::AlignedBytes, &mut crate::AlignedBytes) -> R,
    ) -> Option<R> {
        self.sections
            .with_disjoint_data_mut(read_a, read_b, write, f)
    }

    #[inline]
    pub(crate) fn section_is_override(&self, section: SectionId) -> bool {
        self.sections.is_override(section)
    }

    /// Returns the owner module of `section`, when present.
    #[inline]
    pub fn owner(&self, section: SectionId) -> Option<ModuleId> {
        self.sections.owner(section)
    }

    #[inline]
    pub fn placement(&self, section: SectionId) -> Option<SectionPlacement> {
        self.sections.placement(section)
    }

    /// Iterates over sections that currently have a physical arena placement.
    pub(crate) fn section_placements(
        &self,
    ) -> impl Iterator<Item = (SectionId, SectionPlacement)> + '_ {
        self.sections
            .iter_records()
            .filter_map(|(section, record)| {
                record.placement().map(|placement| (section, placement))
            })
    }

    /// Returns the section id for one scanned section inside one module.
    #[inline]
    pub fn section_id(
        &self,
        module_id: ModuleId,
        id: impl Into<ScannedSectionId>,
    ) -> Option<SectionId> {
        self.module(module_id).section_id(id)
    }

    fn arena_section_placements(
        &self,
        arena: ArenaId,
    ) -> impl Iterator<Item = (SectionId, SectionPlacement)> + '_ {
        self.sections
            .iter_records()
            .filter_map(move |(section, record)| {
                record
                    .placement()
                    .filter(|placement| placement.arena() == arena)
                    .map(|placement| (section, placement))
            })
    }

    /// Returns the derived usage summary for one arena.
    pub fn usage(&self, id: ArenaId) -> ArenaUsage {
        let arena = self.arena(id);
        let mut section_count = 0usize;
        let mut used_len = 0usize;

        for (_, placement) in self.arena_section_placements(id) {
            section_count += 1;
            let section_end = placement
                .offset()
                .checked_add(placement.size())
                .expect("arena usage overflowed while computing section end");
            used_len = used_len.max(section_end);
        }

        let mapped_len = align_up_len(used_len, arena.page_size());
        ArenaUsage::new(section_count, used_len, mapped_len)
    }

    /// Assigns one section to a physical arena at `offset`.
    pub fn assign(
        &mut self,
        section: SectionId,
        arena: ArenaId,
        offset: usize,
    ) -> bool {
        let size = self.section(section).size();
        let placement = SectionPlacement::new(arena, offset, size);
        let metadata = self.section(section);
        if !metadata.is_allocated() || metadata.size() != placement.size() {
            return false;
        }
        let Some(memory_class) = metadata.memory_class() else {
            return false;
        };
        let arena = self.arena(placement.arena());
        if memory_class != arena.memory_class() {
            return false;
        }

        self.sections.set_placement(section, placement)
    }

    pub fn clear_section(&mut self, section: SectionId) -> Option<SectionPlacement> {
        self.sections.clear_placement(section)
    }

    /// Appends one physical arena and returns its stable arena id.
    #[inline]
    pub fn push_arena(&mut self, arena: Arena) -> ArenaId {
        self.arenas.push(arena)
    }

    /// Creates one physical arena and returns its stable arena id.
    #[inline]
    pub fn create_arena(&mut self, arena: Arena) -> ArenaId {
        self.push_arena(arena)
    }

    /// Installs the layout for one module.
    ///
    /// Existing module slots are only placeholders and must still be empty.
    #[inline]
    pub(crate) fn insert_module(&mut self, module_id: ModuleId, layout: ModuleLayout) {
        let _ = self.modules.insert(module_id, layout);
    }

    /// Builds a section-granularity layout seed from scanned metadata.
    pub(crate) fn from_scanned<'a, D, I>(modules: I) -> Self
    where
        D: 'static,
        I: IntoIterator<Item = (ModuleId, &'a ScannedDylib<D>)>,
    {
        let mut plan = Self::default();
        for (module_id, module) in modules {
            let materialization = Materialization::default(module.capability());
            let layout = ModuleLayout::from_scanned(module_id, module, &mut plan.sections);
            plan.insert_module(module_id, layout);
            let _ = plan.set_materialization(module_id, materialization);
        }
        plan
    }
}

fn align_up_len(value: usize, page_size: usize) -> usize {
    let page_size = page_size.max(1);
    let remainder = value % page_size;
    if remainder == 0 {
        return value;
    }
    value
        .checked_add(page_size - remainder)
        .expect("arena usage overflowed while rounding mapped length")
}
