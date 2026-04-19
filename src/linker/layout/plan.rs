use super::{
    arena::{LayoutArena, LayoutArenaId, LayoutArenaUsage},
    section::{
        LayoutSectionArena, LayoutSectionId, LayoutSectionMetadata, ModuleLayout, SectionPlacement,
    },
};
use crate::{
    entity::{PrimaryMap, SecondaryMap},
    image::{ModuleCapability, ScannedDylib, ScannedSectionId},
    linker::plan::LinkModuleId,
};

/// The requested materialization mode for one module during planned load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Materialization {
    /// Materialize the full DSO into a private region with multiple
    /// permission-specific mapped areas derived from `PT_LOAD`.
    #[default]
    WholeDsoRegion,
    /// Materialize alloc sections directly into section regions / arenas.
    SectionRegions,
}

impl Materialization {
    pub(crate) const fn default_for_capability(capability: ModuleCapability) -> Self {
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
pub struct MemoryLayoutPlan {
    arenas: PrimaryMap<LayoutArenaId, LayoutArena>,
    modules: PrimaryMap<LinkModuleId, ModuleLayout>,
    materialization: SecondaryMap<LinkModuleId, Materialization>,
    sections: LayoutSectionArena,
}

impl MemoryLayoutPlan {
    /// Returns the planned physical arenas for the current load session.
    #[inline]
    pub fn arenas(&self) -> &[LayoutArena] {
        self.arenas.as_slice()
    }

    /// Iterates over planned arenas together with their stable arena ids.
    #[inline]
    pub fn arena_entries(&self) -> impl Iterator<Item = (LayoutArenaId, &LayoutArena)> {
        self.arenas.iter()
    }

    /// Returns one arena descriptor by arena id.
    #[inline]
    pub fn arena(&self, id: LayoutArenaId) -> &LayoutArena {
        self.arenas
            .get(id)
            .expect("layout plan referenced missing arena")
    }

    /// Returns one arena descriptor by arena id mutably.
    #[inline]
    pub fn arena_mut(&mut self, id: LayoutArenaId) -> &mut LayoutArena {
        self.arenas
            .get_mut(id)
            .expect("layout plan referenced missing arena")
    }

    /// Returns the planned layout for one module.
    #[inline]
    pub fn module(&self, module_id: LinkModuleId) -> &ModuleLayout {
        self.modules
            .get(module_id)
            .expect("layout plan referenced missing module layout")
    }

    /// Iterates over all planned module layouts.
    #[inline]
    pub fn modules(&self) -> impl Iterator<Item = (LinkModuleId, &ModuleLayout)> {
        self.modules.iter()
    }

    /// Returns the currently configured materialization mode for one module.
    #[inline]
    pub fn module_materialization(&self, module_id: LinkModuleId) -> Option<Materialization> {
        self.materialization.get(module_id).copied()
    }

    /// Updates the planned materialization mode for one module.
    #[inline]
    pub fn set_module_materialization(
        &mut self,
        module_id: LinkModuleId,
        mode: Materialization,
    ) -> Option<Materialization> {
        self.materialization.insert(module_id, mode)
    }

    /// Returns the arena that owns all section records.
    #[inline]
    pub fn sections(&self) -> &LayoutSectionArena {
        &self.sections
    }

    /// Returns the arena that owns all section records mutably.
    #[inline]
    pub fn sections_mut(&mut self) -> &mut LayoutSectionArena {
        &mut self.sections
    }

    /// Returns one section metadata record by internal section id.
    #[inline]
    pub fn section_metadata(&self, id: LayoutSectionId) -> &LayoutSectionMetadata {
        self.sections
            .get(id)
            .expect("layout plan referenced missing section metadata")
    }

    #[inline]
    pub(crate) fn section_overrides_original_data(&self, section: LayoutSectionId) -> bool {
        self.sections.overrides_original_data(section)
    }

    /// Returns the owner module of `section`, when present.
    #[inline]
    pub fn section_owner(&self, section: LayoutSectionId) -> Option<LinkModuleId> {
        self.sections.owner(section)
    }

    /// Returns the direct arena placement of one section.
    #[inline]
    pub fn section_placement(&self, section: LayoutSectionId) -> Option<SectionPlacement> {
        self.sections.placement(section)
    }

    /// Returns whether any section currently has a physical arena placement.
    #[inline]
    pub fn has_section_placements(&self) -> bool {
        self.sections.has_any_placements()
    }

    /// Returns the section id for one scanned section inside one module.
    #[inline]
    pub fn module_section_id(
        &self,
        module_id: LinkModuleId,
        id: impl Into<ScannedSectionId>,
    ) -> Option<LayoutSectionId> {
        self.module(module_id).section_id(id)
    }

    /// Returns one section metadata record by module key and scanned section id.
    #[inline]
    pub fn module_section(
        &self,
        module_id: LinkModuleId,
        id: impl Into<ScannedSectionId>,
    ) -> Option<&LayoutSectionMetadata> {
        self.module_section_id(module_id, id)
            .map(|section| self.section_metadata(section))
    }

    /// Iterates over the placed sections inside one arena.
    pub fn arena_sections(
        &self,
        arena: LayoutArenaId,
    ) -> impl Iterator<Item = LayoutSectionId> + '_ {
        self.arena_section_placements(arena)
            .map(|(section, _)| section)
    }

    fn arena_section_placements(
        &self,
        arena: LayoutArenaId,
    ) -> impl Iterator<Item = (LayoutSectionId, SectionPlacement)> + '_ {
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
    pub fn arena_usage(&self, id: LayoutArenaId) -> LayoutArenaUsage {
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
        LayoutArenaUsage::new(section_count, used_len, mapped_len)
    }

    /// Iterates over arena ids together with their derived usage summaries.
    #[inline]
    pub fn arena_usages(&self) -> impl Iterator<Item = (LayoutArenaId, LayoutArenaUsage)> + '_ {
        self.arena_entries()
            .map(|(id, _)| (id, self.arena_usage(id)))
    }
}

impl MemoryLayoutPlan {
    /// Assigns one section to a physical arena at `offset`.
    pub fn assign_section_to_arena(
        &mut self,
        section: LayoutSectionId,
        arena: LayoutArenaId,
        offset: usize,
    ) -> bool {
        let size = self.section_metadata(section).size();
        self.place_section_in_arena(section, SectionPlacement::new(arena, offset, size))
    }

    /// Assigns one section to a concrete arena placement.
    pub fn place_section_in_arena(
        &mut self,
        section: LayoutSectionId,
        placement: SectionPlacement,
    ) -> bool {
        let metadata = self.section_metadata(section);
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

    pub fn clear_section_arena(&mut self, section: LayoutSectionId) -> Option<SectionPlacement> {
        self.sections.clear_placement(section)
    }

    pub fn clear_arena_mappings(&mut self) {
        self.arenas = PrimaryMap::default();
        self.sections.clear_placements();
    }
}

impl MemoryLayoutPlan {
    /// Appends one physical arena and returns its stable arena id.
    #[inline]
    pub fn push_arena(&mut self, arena: LayoutArena) -> LayoutArenaId {
        self.arenas.push(arena)
    }

    /// Creates one physical arena and returns its stable arena id.
    #[inline]
    pub fn create_arena(&mut self, arena: LayoutArena) -> LayoutArenaId {
        self.push_arena(arena)
    }

    /// Replaces the layout for one module.
    #[inline]
    pub fn insert_module(
        &mut self,
        module_id: LinkModuleId,
        layout: ModuleLayout,
    ) -> Option<ModuleLayout> {
        if let Some(module) = self.modules.get_mut(module_id) {
            let previous = core::mem::replace(module, layout);
            for (_, section_id) in previous.section_entries() {
                self.sections.clear_placement(*section_id);
            }
            if !self.materialization.contains_key(module_id) {
                self.materialization
                    .insert(module_id, Materialization::WholeDsoRegion);
            }
            return Some(previous);
        }

        assert_eq!(
            module_id.index(),
            self.modules.len(),
            "layout modules must be inserted densely in module-id order"
        );
        let inserted_id = self.modules.push(layout);
        assert_eq!(
            inserted_id, module_id,
            "layout module id assignment drifted"
        );
        self.materialization
            .insert(module_id, Materialization::WholeDsoRegion);
        None
    }

    /// Builds a section-granularity layout seed from scanned metadata.
    pub fn seed_from_scanned_modules<'a, D, I>(modules: I) -> Self
    where
        D: 'static,
        I: IntoIterator<Item = (LinkModuleId, &'a ScannedDylib<D>)>,
    {
        let mut plan = Self::default();
        for (module_id, module) in modules {
            let materialization = Materialization::default_for_capability(module.capability());
            let layout = ModuleLayout::from_scanned(module_id, module, &mut plan.sections);
            plan.insert_module(module_id, layout);
            let _ = plan.set_module_materialization(module_id, materialization);
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
