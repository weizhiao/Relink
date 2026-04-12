use super::{
    arena::{LayoutArena, LayoutArenaId, LayoutArenaUsage},
    derived::{
        LayoutAddress, LayoutRetainedRelocationRepair, LayoutSectionRepair, ModuleLayoutDerived,
    },
    section::{
        LayoutSectionArena, LayoutSectionData, LayoutSectionId, LayoutSectionKind,
        LayoutSectionMetadata, ModuleLayout, SectionPlacement,
    },
};
use crate::{
    AlignedBytes, Result,
    entity::{PrimaryMap, SecondaryMap},
    image::{ModuleCapability, ScannedDylib, ScannedSectionId},
    linker::plan::LinkModuleId,
};

/// The requested materialization mode for one module during planned load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LayoutModuleMaterialization {
    /// Materialize the full DSO into a private region with multiple
    /// permission-specific mapped areas derived from `PT_LOAD`.
    #[default]
    WholeDsoRegion,
    /// Materialize alloc sections directly into section regions / arenas.
    SectionRegions,
}

/// A memory-layout core derived from a logical [`super::super::LinkPlan`].
///
/// The logical module graph remains authoritative for dependency resolution and
/// symbol-lookup scope. This type owns section metadata/data together with the
/// physical arena placements selected by planning passes.
#[derive(Debug, Clone)]
pub struct MemoryLayoutPlan {
    arenas: PrimaryMap<LayoutArenaId, LayoutArena>,
    modules: PrimaryMap<LinkModuleId, ModuleLayout>,
    materialization: SecondaryMap<LinkModuleId, LayoutModuleMaterialization>,
    sections: LayoutSectionArena,
    derived: SecondaryMap<LinkModuleId, ModuleLayoutDerived>,
}

impl Default for MemoryLayoutPlan {
    fn default() -> Self {
        Self {
            arenas: PrimaryMap::default(),
            modules: PrimaryMap::default(),
            materialization: SecondaryMap::default(),
            sections: LayoutSectionArena::default(),
            derived: SecondaryMap::default(),
        }
    }
}
impl MemoryLayoutPlan {
    /// Creates an empty memory-layout plan.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

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
    pub fn module(&self, module_id: LinkModuleId) -> Option<&ModuleLayout> {
        self.modules.get(module_id)
    }

    /// Returns the planned layout for one module mutably.
    #[inline]
    pub fn module_mut(&mut self, module_id: LinkModuleId) -> Option<&mut ModuleLayout> {
        self.modules.get_mut(module_id)
    }

    /// Iterates over all planned module layouts.
    #[inline]
    pub fn modules(&self) -> impl Iterator<Item = (LinkModuleId, &ModuleLayout)> {
        self.modules.iter()
    }

    /// Returns the currently configured materialization mode for one module.
    #[inline]
    pub fn module_materialization(
        &self,
        module_id: LinkModuleId,
    ) -> Option<LayoutModuleMaterialization> {
        self.materialization.get(module_id).copied()
    }

    /// Updates the planned materialization mode for one module.
    #[inline]
    pub fn set_module_materialization(
        &mut self,
        module_id: LinkModuleId,
        mode: LayoutModuleMaterialization,
    ) -> Option<LayoutModuleMaterialization> {
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

    /// Returns the relocation-section metadata for one module.
    #[inline]
    pub fn relocation_section(
        &self,
        module_id: LinkModuleId,
        id: ScannedSectionId,
    ) -> Option<&LayoutSectionMetadata> {
        self.module_section(module_id, id)
            .filter(|section| section.is_relocation())
    }

    /// Returns the section id for one scanned section inside one module.
    #[inline]
    pub fn module_section_id(
        &self,
        module_id: LinkModuleId,
        id: ScannedSectionId,
    ) -> Option<LayoutSectionId> {
        self.module(module_id)
            .and_then(|module| module.section_id(id))
    }

    /// Returns one section metadata record by module key and scanned section id.
    #[inline]
    pub fn module_section(
        &self,
        module_id: LinkModuleId,
        id: ScannedSectionId,
    ) -> Option<&LayoutSectionMetadata> {
        self.module_section_id(module_id, id)
            .map(|section| self.section_metadata(section))
    }

    /// Iterates over the placed sections inside one arena.
    pub fn arena_sections(
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

    #[inline]
    pub(crate) fn module_derived(&self, module_id: LinkModuleId) -> Option<&ModuleLayoutDerived> {
        self.derived.get(module_id)
    }

    /// Returns one section-base repair entry for a module.
    #[inline]
    pub fn section_repair(
        &self,
        module_id: LinkModuleId,
        id: LayoutSectionId,
    ) -> Option<LayoutSectionRepair> {
        self.module_derived(module_id)
            .and_then(|derived| derived.section_repair(id))
    }

    /// Returns one retained-relocation repair entry for a module.
    #[inline]
    pub fn relocation_repair(
        &self,
        module_id: LinkModuleId,
        id: LayoutSectionId,
    ) -> Option<&LayoutRetainedRelocationRepair> {
        self.module_derived(module_id)
            .and_then(|derived| derived.relocation_repair(id))
    }

    /// Returns one derived relocation-site address for a module.
    #[inline]
    pub fn relocation_site_address(
        &self,
        module_id: LinkModuleId,
        relocation_section: LayoutSectionId,
        entry_index: usize,
    ) -> Option<LayoutAddress> {
        self.module_derived(module_id)
            .and_then(|derived| derived.relocation_site_address(relocation_section, entry_index))
    }

    /// Returns the derived usage summary for one arena.
    pub fn arena_usage(&self, id: LayoutArenaId) -> Option<LayoutArenaUsage> {
        let arena = self.arena(id);
        let mut section_count = 0usize;
        let mut used_len = 0usize;

        for (_, placement) in self.arena_sections(id) {
            section_count += 1;
            let section_end = placement.offset().checked_add(placement.size())?;
            used_len = used_len.max(section_end);
        }

        let mapped_len = align_up_len(used_len, arena.page_size())?;
        Some(LayoutArenaUsage::new(section_count, used_len, mapped_len))
    }

    /// Iterates over arena ids together with their derived usage summaries.
    #[inline]
    pub fn arena_usages(&self) -> impl Iterator<Item = (LayoutArenaId, LayoutArenaUsage)> + '_ {
        self.arena_entries()
            .filter_map(|(id, _)| self.arena_usage(id).map(|usage| (id, usage)))
    }
}

impl MemoryLayoutPlan {
    /// Materializes section data for `section`.
    pub(crate) fn install_section_data(
        &mut self,
        section: LayoutSectionId,
        bytes: impl Into<AlignedBytes>,
    ) -> Option<LayoutSectionId> {
        let metadata = self.sections.get(section)?;
        if metadata.zero_fill() {
            self.sections.install_data(
                section,
                LayoutSectionData::ZeroFill {
                    size: metadata.size(),
                },
            )?;
        } else {
            self.sections.push_scanned(section, bytes.into())?;
        }
        Some(section)
    }

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
        let arena = self.arena(placement.arena());
        if !matches!(
            metadata.kind(),
            LayoutSectionKind::Allocated(class) if class == arena.memory_class()
        ) {
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
        self.derived = SecondaryMap::default();
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
            for section_id in previous.sections() {
                self.sections.clear_placement(*section_id);
            }
            self.derived.remove(module_id);
            if !self.materialization.contains_key(module_id) {
                self.materialization
                    .insert(module_id, LayoutModuleMaterialization::WholeDsoRegion);
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
            .insert(module_id, LayoutModuleMaterialization::WholeDsoRegion);
        None
    }

    /// Rebuilds the core relocation/repair state derived from section placements.
    pub fn rebuild_derived_state(
        &mut self,
        mut module_capability: impl FnMut(LinkModuleId) -> Option<ModuleCapability>,
    ) -> Result<()> {
        let mut derived = SecondaryMap::default();
        for (module_id, module) in self.modules.iter() {
            let capability = module_capability(module_id).unwrap_or(ModuleCapability::SectionData);
            let module_derived =
                ModuleLayoutDerived::from_layout(module, capability, &self.sections)?;
            derived.insert(module_id, module_derived);
        }
        self.derived = derived;
        Ok(())
    }

    /// Builds a section-granularity layout seed from scanned metadata.
    pub fn seed_from_scanned_modules<'a, D, I>(modules: I) -> Self
    where
        D: 'static,
        I: IntoIterator<Item = (LinkModuleId, &'a ScannedDylib<D>)>,
    {
        let mut plan = Self::new();
        for (module_id, module) in modules {
            let layout = ModuleLayout::from_scanned(module_id, module, &mut plan.sections);
            plan.insert_module(module_id, layout);
        }
        plan
    }
}

fn align_up_len(value: usize, page_size: usize) -> Option<usize> {
    let page_size = page_size.max(1);
    let remainder = value % page_size;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(page_size - remainder)
}
