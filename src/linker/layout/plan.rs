use super::{
    address::{LayoutAddress, LayoutAddressMap, ModuleAddressMap},
    arena::{LayoutArena, LayoutArenaId, LayoutArenaUsage},
    physical::{LayoutPhysicalImage, LayoutPhysicalPlan, ModulePhysicalLayout},
    region::{
        LayoutRegion, LayoutRegionArena, LayoutRegionId, LayoutRegionPlacement,
        SectionRegionPlacement,
    },
    repair::{
        LayoutRepairPlan, LayoutRepairStatus, LayoutRetainedRelocationRepair, LayoutSectionRepair,
        ModuleLayoutRepair,
    },
    section::{
        LayoutRetainedRelocationSection, LayoutSectionData, LayoutSectionDataArena,
        LayoutSectionDataId, LayoutSectionId, LayoutSectionMetadata, LayoutSectionMetadataArena,
        ModuleLayout, SectionPlacement,
    },
};
use crate::{
    Result,
    entity::EntityArena,
    image::{
        ScannedDylib, ScannedMemorySection, ScannedRelocationSection, ScannedSection,
        ScannedSectionId,
    },
};
use alloc::{collections::BTreeMap, vec::Vec};

/// A memory-layout core derived from a logical [`super::super::LinkPlan`].
///
/// The logical module graph remains authoritative for dependency resolution and
/// symbol-lookup scope. This type owns the core two-level layout mechanism:
/// sections attach to logical regions, logical regions map into physical
/// arenas, and derived addresses are rebuilt from those mappings.
#[derive(Debug, Clone)]
pub struct MemoryLayoutPlan<K> {
    arenas: EntityArena<LayoutArenaId, LayoutArena>,
    regions: LayoutRegionArena,
    modules: BTreeMap<K, ModuleLayout>,
    section_owners: BTreeMap<LayoutSectionId, K>,
    region_owners: BTreeMap<LayoutRegionId, K>,
    section_metadata: LayoutSectionMetadataArena,
    section_data: LayoutSectionDataArena,
    addresses: LayoutAddressMap<K>,
    physical: LayoutPhysicalPlan<K>,
    repairs: LayoutRepairPlan<K>,
}

impl<K> Default for MemoryLayoutPlan<K> {
    #[inline]
    fn default() -> Self {
        Self {
            arenas: EntityArena::default(),
            regions: LayoutRegionArena::default(),
            modules: BTreeMap::new(),
            section_owners: BTreeMap::new(),
            region_owners: BTreeMap::new(),
            section_metadata: LayoutSectionMetadataArena::default(),
            section_data: LayoutSectionDataArena::default(),
            addresses: LayoutAddressMap::default(),
            physical: LayoutPhysicalPlan::default(),
            repairs: LayoutRepairPlan::default(),
        }
    }
}

impl<K> MemoryLayoutPlan<K>
where
    K: Ord,
{
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
    pub fn arena(&self, id: LayoutArenaId) -> Option<&LayoutArena> {
        self.arenas.get(id)
    }

    /// Returns one arena descriptor by arena id mutably.
    #[inline]
    pub fn arena_mut(&mut self, id: LayoutArenaId) -> Option<&mut LayoutArena> {
        self.arenas.get_mut(id)
    }

    /// Returns the arena that owns all logical regions.
    #[inline]
    pub fn region_arena(&self) -> &LayoutRegionArena {
        &self.regions
    }

    /// Returns the arena that owns all logical regions mutably.
    #[inline]
    pub fn region_arena_mut(&mut self) -> &mut LayoutRegionArena {
        &mut self.regions
    }

    /// Returns one logical region by region id.
    #[inline]
    pub fn region(&self, id: LayoutRegionId) -> Option<&LayoutRegion> {
        self.regions.get(id)
    }

    /// Returns one logical region by region id mutably.
    #[inline]
    pub fn region_mut(&mut self, id: LayoutRegionId) -> Option<&mut LayoutRegion> {
        self.regions.get_mut(id)
    }

    /// Iterates over every logical region together with its region id.
    #[inline]
    pub fn region_entries(&self) -> impl Iterator<Item = (LayoutRegionId, &LayoutRegion)> {
        self.regions.iter()
    }

    /// Returns the planned layout for one module.
    #[inline]
    pub fn module(&self, key: &K) -> Option<&ModuleLayout> {
        self.modules.get(key)
    }

    /// Returns the planned layout for one module mutably.
    #[inline]
    pub fn module_mut(&mut self, key: &K) -> Option<&mut ModuleLayout> {
        self.modules.get_mut(key)
    }

    /// Iterates over all planned module layouts.
    #[inline]
    pub fn modules(&self) -> impl Iterator<Item = (&K, &ModuleLayout)> {
        self.modules.iter()
    }

    /// Returns the arena that owns all section metadata records.
    #[inline]
    pub fn section_metadata_arena(&self) -> &LayoutSectionMetadataArena {
        &self.section_metadata
    }

    /// Returns the arena that owns all section metadata records mutably.
    #[inline]
    pub fn section_metadata_arena_mut(&mut self) -> &mut LayoutSectionMetadataArena {
        &mut self.section_metadata
    }

    /// Returns the arena that owns materialized section data.
    #[inline]
    pub fn section_data_arena(&self) -> &LayoutSectionDataArena {
        &self.section_data
    }

    /// Returns the arena that owns materialized section data mutably.
    #[inline]
    pub fn section_data_arena_mut(&mut self) -> &mut LayoutSectionDataArena {
        &mut self.section_data
    }

    /// Returns one section metadata record by internal section id.
    #[inline]
    pub fn section_metadata(&self, id: LayoutSectionId) -> Option<&LayoutSectionMetadata> {
        self.section_metadata.get(id)
    }

    /// Returns one section metadata record by internal section id mutably.
    #[inline]
    pub fn section_metadata_mut(
        &mut self,
        id: LayoutSectionId,
    ) -> Option<&mut LayoutSectionMetadata> {
        self.section_metadata.get_mut(id)
    }

    /// Returns one materialized section-data view by internal data id.
    #[inline]
    pub fn section_data(&self, id: LayoutSectionDataId) -> Option<&LayoutSectionData> {
        self.section_data.get(id)
    }

    /// Returns the logical region assignment for one section.
    #[inline]
    pub fn section_region(&self, section: LayoutSectionId) -> Option<SectionRegionPlacement> {
        self.section_metadata(section)
            .and_then(LayoutSectionMetadata::region)
    }

    /// Returns the physical placement of one logical region.
    #[inline]
    pub fn region_placement(&self, region: LayoutRegionId) -> Option<LayoutRegionPlacement> {
        self.region(region).and_then(LayoutRegion::placement)
    }

    /// Returns whether any logical region currently has a physical arena placement.
    #[inline]
    pub fn has_region_placements(&self) -> bool {
        self.region_entries()
            .any(|(_, region)| region.placement().is_some())
    }

    /// Builds a concrete arena image from the current physical placements and
    /// any section bytes already materialized into the plan.
    pub fn build_physical_image(&self) -> Result<Option<LayoutPhysicalImage<K>>>
    where
        K: Clone,
    {
        if !self.has_region_placements() {
            return Ok(None);
        }

        let mut image = LayoutPhysicalImage::new();
        for (arena_id, arena) in self.arena_entries() {
            let len = self
                .arena_usage(arena_id)
                .map(LayoutArenaUsage::mapped_len)
                .unwrap_or(0);
            image.insert_arena(arena_id, *arena, len);
        }

        for (section_id, metadata) in self.section_metadata.iter() {
            let Some(section) = metadata.region() else {
                continue;
            };
            let Some(region) = self.region_placement(section.region()) else {
                continue;
            };
            let Some(placement) = SectionPlacement::from_region(region, section) else {
                return Err(crate::custom_error(
                    "layout physical image overflowed while deriving a section placement",
                ));
            };

            let end = placement
                .offset()
                .checked_add(placement.size())
                .ok_or_else(|| {
                    crate::custom_error(
                        "layout physical image overflowed while computing section bounds",
                    )
                })?;
            let arena = image.arena_bytes_mut(placement.arena()).ok_or_else(|| {
                crate::custom_error("layout physical image referenced a missing arena buffer")
            })?;
            let dst = arena.get_mut(placement.offset()..end).ok_or_else(|| {
                crate::custom_error("layout physical image section placement exceeds arena bounds")
            })?;

            if metadata.zero_fill() {
                continue;
            }

            let data_id = metadata.data().ok_or_else(|| {
                crate::custom_error("layout physical image is missing materialized section data")
            })?;
            let data = self.section_data(data_id).ok_or_else(|| {
                crate::custom_error(
                    "layout physical image referenced a missing section-data record",
                )
            })?;

            match data {
                LayoutSectionData::Bytes(bytes) => {
                    if bytes.len() != dst.len() {
                        return Err(crate::custom_error(
                            "layout physical image section size does not match its materialized bytes",
                        ));
                    }
                    dst.copy_from_slice(bytes);
                }
                LayoutSectionData::ZeroFill { .. } => {}
            }

            let _ = section_id;
        }

        for (key, module) in self.physical.modules() {
            image.insert_module(key.clone(), module.clone());
        }

        Ok(Some(image))
    }

    /// Returns one relocation section for a module.
    #[inline]
    pub fn relocation_section(
        &self,
        key: &K,
        id: ScannedSectionId,
    ) -> Option<&LayoutRetainedRelocationSection> {
        self.module_section(key, id)
            .and_then(LayoutSectionMetadata::retained_relocations)
    }

    /// Iterates over relocation sections for `key` that target `target`.
    #[inline]
    pub fn relocation_sections_for_target(
        &self,
        key: &K,
        target: ScannedSectionId,
    ) -> impl Iterator<Item = &LayoutRetainedRelocationSection> {
        self.module(key)
            .into_iter()
            .flat_map(|module| module.section_entries())
            .filter_map(|(_, section_id)| self.section_metadata(*section_id))
            .filter_map(LayoutSectionMetadata::retained_relocations)
            .filter(move |section| section.target_section() == Some(target))
    }

    /// Returns the section id for one scanned section inside one module.
    #[inline]
    pub fn module_section_id(&self, key: &K, id: ScannedSectionId) -> Option<LayoutSectionId> {
        self.module(key).and_then(|module| module.section_id(id))
    }

    /// Returns one section metadata record by module key and scanned section id.
    #[inline]
    pub fn module_section(&self, key: &K, id: ScannedSectionId) -> Option<&LayoutSectionMetadata> {
        self.module_section_id(key, id)
            .and_then(|section| self.section_metadata(section))
    }

    /// Returns the logical region assignment for one section inside one module.
    #[inline]
    pub fn module_section_region(
        &self,
        key: &K,
        id: ScannedSectionId,
    ) -> Option<SectionRegionPlacement> {
        self.module_section(key, id)
            .and_then(LayoutSectionMetadata::region)
    }

    /// Returns one materialized section-data view by module key and scanned section id.
    #[inline]
    pub fn module_section_data(&self, key: &K, id: ScannedSectionId) -> Option<&LayoutSectionData> {
        self.module_section(key, id)
            .and_then(|section| section.data())
            .and_then(|data| self.section_data(data))
    }

    /// Returns the module that owns one internal section id.
    #[inline]
    pub fn section_owner(&self, section: LayoutSectionId) -> Option<&K> {
        self.section_owners.get(&section)
    }

    /// Returns the module that owns one logical region.
    #[inline]
    pub fn region_owner(&self, region: LayoutRegionId) -> Option<&K> {
        self.region_owners.get(&region)
    }

    /// Returns whether the built-in reorder-repair machinery can handle `key`.
    ///
    /// Today this requires retained relocation metadata, typically produced by
    /// `-emit-relocs`. When this returns `false`, callers can still place the
    /// module, but they should treat aggressive section reordering as unsafe.
    #[inline]
    pub fn supports_reorder_repair(&self, key: &K) -> bool {
        self.module(key)
            .into_iter()
            .flat_map(|module| module.section_entries())
            .filter_map(|(_, section_id)| self.section_metadata(*section_id))
            .any(|section| section.retained_relocations().is_some())
    }

    /// Returns the derived address map.
    #[inline]
    pub fn addresses(&self) -> &LayoutAddressMap<K> {
        &self.addresses
    }

    /// Returns the derived address map mutably.
    #[inline]
    pub fn addresses_mut(&mut self) -> &mut LayoutAddressMap<K> {
        &mut self.addresses
    }

    /// Returns the derived physical DSO layouts.
    #[inline]
    pub fn physical(&self) -> &LayoutPhysicalPlan<K> {
        &self.physical
    }

    /// Returns the derived physical layout for one module.
    #[inline]
    pub fn module_physical_layout(&self, key: &K) -> Option<&ModulePhysicalLayout> {
        self.physical.module(key)
    }

    /// Returns whether `key` currently owns any bytes inside `arena`.
    #[inline]
    pub fn module_touches_arena(&self, key: &K, arena: LayoutArenaId) -> bool {
        self.physical.touches_arena(key, arena)
    }

    /// Iterates over modules that currently own bytes inside `arena`.
    #[inline]
    pub fn modules_in_arena(
        &self,
        arena: LayoutArenaId,
    ) -> impl Iterator<Item = (&K, &ModulePhysicalLayout)> {
        self.physical.modules_in_arena(arena)
    }

    /// Returns the derived reorder-repair plans.
    #[inline]
    pub fn repairs(&self) -> &LayoutRepairPlan<K> {
        &self.repairs
    }

    /// Returns the derived reorder-repair plan for one module.
    #[inline]
    pub fn module_repair(&self, key: &K) -> Option<&ModuleLayoutRepair> {
        self.repairs.module(key)
    }

    /// Returns the current reorder-repair state for one module.
    #[inline]
    pub fn repair_status(&self, key: &K) -> LayoutRepairStatus {
        self.module_repair(key)
            .map(ModuleLayoutRepair::status)
            .unwrap_or(LayoutRepairStatus::NotNeeded)
    }

    /// Returns one section-base repair entry for a module.
    #[inline]
    pub fn section_repair(&self, key: &K, id: ScannedSectionId) -> Option<&LayoutSectionRepair> {
        self.module_repair(key)
            .and_then(|repair| repair.section_repair(id))
    }

    /// Returns one retained-relocation repair entry for a module.
    #[inline]
    pub fn relocation_repair(
        &self,
        key: &K,
        id: ScannedSectionId,
    ) -> Option<&LayoutRetainedRelocationRepair> {
        self.module_repair(key)
            .and_then(|repair| repair.relocation_repair(id))
    }

    /// Returns one derived section address for a module.
    #[inline]
    pub fn section_address(&self, key: &K, id: ScannedSectionId) -> Option<LayoutAddress> {
        self.addresses.section_address(key, id)
    }

    /// Returns one placed section reference for a module.
    #[inline]
    pub fn section_placement(&self, key: &K, id: ScannedSectionId) -> Option<SectionPlacement> {
        self.addresses.section_placement(key, id)
    }

    /// Returns the arena that hosts one placed section for a module.
    #[inline]
    pub fn section_arena(&self, key: &K, id: ScannedSectionId) -> Option<LayoutArenaId> {
        self.section_placement(key, id).map(SectionPlacement::arena)
    }

    /// Returns one derived relocation-site address for a module.
    #[inline]
    pub fn relocation_site_address(
        &self,
        key: &K,
        relocation_section: ScannedSectionId,
        entry_index: usize,
    ) -> Option<LayoutAddress> {
        self.addresses
            .relocation_site_address(key, relocation_section, entry_index)
    }

    /// Returns the derived usage summary for one arena.
    pub fn arena_usage(&self, id: LayoutArenaId) -> Option<LayoutArenaUsage> {
        let arena = self.arena(id)?;
        let mut section_count = 0usize;
        let mut used_len = 0usize;

        for (_, region) in self.regions.iter() {
            let Some(placement) = region.placement() else {
                continue;
            };
            if placement.arena() != id {
                continue;
            }

            section_count += region.sections().len();
            let region_end = placement.offset().checked_add(placement.size())?;
            used_len = used_len.max(region_end);
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

    fn rebuild_region_shape(&mut self, region_id: LayoutRegionId) {
        let mut sections = Vec::new();
        let mut alignment = 1usize;
        let mut size = 0usize;

        for (section_id, metadata) in self.section_metadata.iter() {
            let Some(region) = metadata.region() else {
                continue;
            };
            if region.region() != region_id {
                continue;
            }
            sections.push(section_id);
            alignment = alignment.max(metadata.alignment());
            size = size.max(region.offset().saturating_add(region.size()));
        }

        if let Some(region) = self.regions.get_mut(region_id) {
            region.rebuild_shape(sections, alignment, size);
        }
    }
}

impl<K> MemoryLayoutPlan<K>
where
    K: Ord,
{
    /// Interns one allocatable scanned section into the section-metadata arena.
    pub fn push_scanned_section(&mut self, section: ScannedSection<'_>) -> LayoutSectionId {
        self.section_metadata
            .insert(LayoutSectionMetadata::from_scanned(section))
    }

    /// Materializes the section data for `section` from a scanned memory snapshot.
    pub fn install_section_data(
        &mut self,
        section: LayoutSectionId,
        snapshot: ScannedMemorySection,
    ) -> Option<LayoutSectionDataId> {
        let metadata = self.section_metadata.get_mut(section)?;
        if let Some(data_id) = metadata.data() {
            return Some(data_id);
        }

        let data = snapshot.into_data();
        let data_id = self.section_data.push(data);
        metadata.set_data(data_id);
        Some(data_id)
    }

    /// Assigns one section to a logical region at `offset`.
    pub fn assign_section_to_region(
        &mut self,
        section: LayoutSectionId,
        region: LayoutRegionId,
        offset: usize,
    ) -> bool {
        let Some(metadata) = self.section_metadata.get(section) else {
            return false;
        };
        let Some(layout_region) = self.regions.get(region) else {
            return false;
        };
        let Some(section_owner) = self.section_owners.get(&section) else {
            return false;
        };
        let Some(region_owner) = self.region_owners.get(&region) else {
            return false;
        };
        if section_owner != region_owner {
            return false;
        }
        if layout_region.memory_class() != metadata.memory_class() {
            return false;
        }

        let previous_region = metadata.region().map(SectionRegionPlacement::region);
        let region_member = SectionRegionPlacement::new(region, offset, metadata.size());

        let Some(metadata) = self.section_metadata.get_mut(section) else {
            return false;
        };
        metadata.set_region(region_member);

        if let Some(previous_region) = previous_region {
            self.rebuild_region_shape(previous_region);
        }
        self.rebuild_region_shape(region);
        true
    }

    /// Clears the logical region assignment of one section.
    pub fn clear_section_region(
        &mut self,
        section: LayoutSectionId,
    ) -> Option<SectionRegionPlacement> {
        let region = self
            .section_metadata
            .get_mut(section)
            .and_then(LayoutSectionMetadata::clear_region)?;
        self.rebuild_region_shape(region.region());
        Some(region)
    }

    /// Assigns a physical placement to one logical region.
    pub fn place_region(
        &mut self,
        region: LayoutRegionId,
        placement: LayoutRegionPlacement,
    ) -> bool {
        let Some(layout_region) = self.regions.get_mut(region) else {
            return false;
        };
        if placement.size() < layout_region.size() {
            return false;
        }
        layout_region.set_placement(placement);
        true
    }

    /// Clears the physical placement of one logical region.
    #[inline]
    pub fn clear_region_placement(
        &mut self,
        region: LayoutRegionId,
    ) -> Option<LayoutRegionPlacement> {
        self.regions
            .get_mut(region)
            .and_then(LayoutRegion::clear_placement)
    }

    /// Clears every physical arena mapping while keeping logical region assignments.
    pub fn clear_region_mappings(&mut self) {
        self.arenas = EntityArena::default();
        self.addresses = LayoutAddressMap::default();
        self.physical = LayoutPhysicalPlan::default();
        self.repairs = LayoutRepairPlan::default();
        for (_, region) in self.regions.iter_mut() {
            region.clear_placement();
        }
    }

    /// Clears every logical region assignment and every physical mapping.
    pub fn clear_regions(&mut self) {
        self.clear_region_mappings();
        self.regions = LayoutRegionArena::default();
        self.region_owners.clear();
        for (_, section) in self.section_metadata.iter_mut() {
            section.clear_region();
        }
    }
}

impl<K> MemoryLayoutPlan<K>
where
    K: Clone + Ord,
{
    /// Inserts one logical layout region owned by `key`.
    #[inline]
    pub fn push_region(&mut self, key: &K, region: LayoutRegion) -> Option<LayoutRegionId> {
        if self.module(key).is_none() {
            return None;
        }

        let region_id = self.regions.insert(region);
        self.region_owners.insert(region_id, key.clone());
        Some(region_id)
    }

    /// Appends one physical arena and returns its stable arena id.
    #[inline]
    pub fn push_arena(&mut self, arena: LayoutArena) -> LayoutArenaId {
        self.arenas.push(arena)
    }

    /// Returns the id of an existing matching arena or appends a new one.
    #[inline]
    pub fn ensure_arena(&mut self, arena: LayoutArena) -> LayoutArenaId {
        if let Some((id, _)) = self.arenas.iter().find(|(_, existing)| *existing == &arena) {
            return id;
        }
        self.push_arena(arena)
    }

    /// Replaces the layout for one module.
    #[inline]
    pub fn insert_module(&mut self, key: K, layout: ModuleLayout) -> Option<ModuleLayout> {
        if let Some(previous) = self.modules.get(&key) {
            for (_, section_id) in previous.section_entries() {
                self.section_owners.remove(section_id);
            }
        }
        for (_, section_id) in layout.section_entries() {
            self.section_owners.insert(*section_id, key.clone());
        }
        self.modules.insert(key, layout)
    }

    /// Interns one retained relocation section into the target module metadata.
    pub fn push_relocation_section(
        &mut self,
        key: &K,
        section: ScannedRelocationSection,
    ) -> Option<LayoutSectionId> {
        let module = self.module(key)?;
        let scanned_section = section.id();
        if let Some(existing) = module.section_id(scanned_section) {
            return Some(existing);
        }
        let section_id = self
            .section_metadata
            .insert(LayoutSectionMetadata::from_relocation(section));
        self.section_owners.insert(section_id, key.clone());
        self.module_mut(key)?
            .insert_section(scanned_section, section_id);
        Some(section_id)
    }

    /// Rebuilds the core derived-address and relocation-site view.
    ///
    /// Custom layout plugins are expected to mutate logical regions and arena
    /// placements, then hand control back to this method instead of
    /// reimplementing section-address repair on their own. This also rebuilds
    /// the reorder-repair worklists derived from retained relocations.
    pub fn rebuild_addresses(&mut self) {
        let mut addresses = LayoutAddressMap::new();
        let mut physical = LayoutPhysicalPlan::new();
        let mut repairs = LayoutRepairPlan::new();
        for (key, module) in self.modules.iter() {
            let module_physical = ModulePhysicalLayout::from_layout(
                key,
                module,
                &self.section_metadata,
                &self.regions,
                &self.region_owners,
            );
            let module_addresses =
                ModuleAddressMap::from_layout(module, &self.section_metadata, &self.regions);
            let module_repairs =
                ModuleLayoutRepair::from_layout(module, &self.section_metadata, &module_addresses);
            physical.insert_module(key.clone(), module_physical);
            repairs.insert_module(key.clone(), module_repairs);
            addresses.insert_module(key.clone(), module_addresses);
        }
        self.addresses = addresses;
        self.physical = physical;
        self.repairs = repairs;
    }

    /// Builds a section-granularity layout seed from scanned metadata.
    ///
    /// This is the default starting point for layout plugins. Each allocatable
    /// section becomes one planned section with no region assignment yet.
    pub fn seed_from_scanned_modules<'a, D, I>(modules: I) -> Self
    where
        D: 'static,
        I: IntoIterator<Item = (&'a K, &'a ScannedDylib<D>)>,
        K: 'a,
    {
        let mut plan = Self::new();
        for (key, module) in modules {
            let layout = ModuleLayout::from_scanned(module, &mut plan.section_metadata);
            plan.insert_module(key.clone(), layout);
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
