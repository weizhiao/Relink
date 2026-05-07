use super::{
    arena::{Arena, ArenaId, ArenaUsage},
    section::{
        DataAccess, LayoutSectionArena, ModuleLayout, SectionDataAccessRef, SectionId,
        SectionMetadata, SectionPlacement,
    },
};
use crate::{
    AlignedBytes,
    entity::{PrimaryMap, SecondaryMap},
    image::{AnyScannedDynamic, ModuleCapability, ScannedSectionId},
    linker::plan::ModuleId,
    segment::align_up,
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
pub(in crate::linker) struct MemoryLayoutPlan {
    arenas: PrimaryMap<ArenaId, Arena>,
    modules: SecondaryMap<ModuleId, ModuleLayout>,
    materialization: SecondaryMap<ModuleId, Materialization>,
    sections: LayoutSectionArena,
}

impl MemoryLayoutPlan {
    /// Returns the planned physical arenas for the current load session.
    #[inline]
    pub(in crate::linker) fn arenas(&self) -> &[Arena] {
        self.arenas.as_slice()
    }

    /// Iterates over planned arenas together with their stable arena ids.
    #[inline]
    pub(in crate::linker) fn arena_pairs(&self) -> impl Iterator<Item = (ArenaId, &Arena)> {
        self.arenas.iter()
    }

    /// Returns one arena descriptor by arena id.
    #[inline]
    pub(in crate::linker) fn arena(&self, id: ArenaId) -> &Arena {
        self.arenas
            .get(id)
            .expect("layout plan referenced missing arena")
    }

    /// Returns the planned layout for one module.
    #[inline]
    pub(in crate::linker) fn module(&self, module_id: ModuleId) -> &ModuleLayout {
        self.modules
            .get(module_id)
            .expect("layout plan referenced missing module layout")
    }

    /// Iterates over all planned module layouts.
    #[inline]
    pub(in crate::linker) fn modules(&self) -> impl Iterator<Item = (ModuleId, &ModuleLayout)> {
        self.modules.iter()
    }

    /// Returns the currently configured materialization mode for one module.
    #[inline]
    pub(in crate::linker) fn materialization(
        &self,
        module_id: ModuleId,
    ) -> Option<Materialization> {
        self.materialization.get(module_id).copied()
    }

    /// Updates the planned materialization mode for one module.
    #[inline]
    pub(in crate::linker) fn set_materialization(
        &mut self,
        module_id: ModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.materialization.insert(module_id, mode)
    }

    /// Returns the arena that owns all section records.
    #[inline]
    pub(in crate::linker) fn sections(
        &self,
    ) -> impl Iterator<Item = (SectionId, &SectionMetadata)> {
        self.sections.iter()
    }

    /// Returns one section metadata record by internal section id.
    #[inline]
    pub(in crate::linker) fn section(&self, id: SectionId) -> &SectionMetadata {
        self.sections
            .get(id)
            .expect("layout plan referenced missing section metadata")
    }

    /// Returns one section's materialized data, when present.
    #[inline]
    pub(in crate::linker) fn data(&self, section: SectionId) -> Option<&AlignedBytes> {
        self.sections.data(section)
    }

    #[inline]
    pub(in crate::linker) fn data_mut(&mut self, section: SectionId) -> Option<&mut AlignedBytes> {
        self.sections.data_mut(section)
    }

    #[inline]
    pub(in crate::linker) fn install_data(&mut self, section: SectionId, bytes: AlignedBytes) {
        self.sections.install_data(section, bytes);
    }

    #[inline]
    pub(in crate::linker) fn mark_section_data_override(&mut self, section: SectionId) {
        self.sections.mark_data_override(section);
    }

    #[inline]
    pub(in crate::linker) fn with_disjoint_section_data<const N: usize, R>(
        &mut self,
        accesses: [(SectionId, DataAccess); N],
        f: impl FnOnce([SectionDataAccessRef<'_>; N]) -> R,
    ) -> Option<R> {
        self.sections.with_disjoint_data(accesses, f)
    }

    #[inline]
    pub(in crate::linker) fn section_is_override(&self, section: SectionId) -> bool {
        self.sections.is_override(section)
    }

    /// Returns the owner module of `section`, when present.
    #[inline]
    pub(in crate::linker) fn owner(&self, section: SectionId) -> Option<ModuleId> {
        self.sections.owner(section)
    }

    #[inline]
    pub(in crate::linker) fn placement(&self, section: SectionId) -> Option<SectionPlacement> {
        self.sections.placement(section)
    }

    /// Iterates over sections that currently have a physical arena placement.
    pub(in crate::linker) fn section_placements(
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
    pub(in crate::linker) fn section_id(
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
    pub(in crate::linker) fn usage(&self, id: ArenaId) -> ArenaUsage {
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

        let mapped_len = align_up(used_len, arena.page_size().bytes());
        ArenaUsage::new(section_count, used_len, mapped_len)
    }

    /// Returns the next aligned placement offset inside `arena`.
    pub(in crate::linker) fn next_offset(&self, arena: ArenaId, alignment: usize) -> usize {
        align_up(self.usage(arena).used_len(), alignment)
    }

    #[inline]
    fn placement_for(
        &self,
        section: SectionId,
        arena: ArenaId,
        offset: usize,
    ) -> Option<SectionPlacement> {
        let metadata = self.section(section);
        if !metadata.is_allocated() {
            return None;
        }
        let memory_class = metadata.memory_class()?;
        if memory_class != self.arena(arena).memory_class() {
            return None;
        }

        Some(SectionPlacement::new(arena, offset, metadata.size()))
    }

    /// Assigns one section to the next aligned offset in a physical arena.
    pub(in crate::linker) fn assign_next(&mut self, section: SectionId, arena: ArenaId) -> bool {
        let offset = self.next_offset(arena, self.section(section).alignment());
        self.assign(section, arena, offset)
    }

    /// Assigns one section to a physical arena at an explicit `offset`.
    pub(in crate::linker) fn assign(
        &mut self,
        section: SectionId,
        arena: ArenaId,
        offset: usize,
    ) -> bool {
        let Some(placement) = self.placement_for(section, arena, offset) else {
            return false;
        };

        self.sections.set_placement(section, placement)
    }

    pub(in crate::linker) fn clear_section(
        &mut self,
        section: SectionId,
    ) -> Option<SectionPlacement> {
        self.sections.clear_placement(section)
    }

    /// Creates one physical arena and returns its stable arena id.
    #[inline]
    pub(in crate::linker) fn create_arena(&mut self, arena: Arena) -> ArenaId {
        self.arenas.push(arena)
    }

    /// Builds a section-granularity layout seed from scanned metadata.
    pub(in crate::linker) fn from_scanned<'a, I>(modules: I) -> Self
    where
        I: IntoIterator<Item = (ModuleId, &'a AnyScannedDynamic)>,
    {
        let mut plan = Self::default();
        for (module_id, module) in modules {
            let layout = ModuleLayout::from_scanned(module_id, module, &mut plan.sections);
            plan.modules.insert(module_id, layout);
        }
        plan
    }
}
