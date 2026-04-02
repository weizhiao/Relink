use super::{
    arena::LayoutArenaId,
    region::LayoutRegionArena,
    section::{LayoutSectionMetadata, LayoutSectionMetadataArena, ModuleLayout, SectionPlacement},
};
use crate::image::ScannedSectionId;
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// A derived address for one placed section or relocation site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutAddress {
    arena: LayoutArenaId,
    offset: usize,
}

impl LayoutAddress {
    /// Creates a new address inside one arena.
    #[inline]
    pub const fn new(arena: LayoutArenaId, offset: usize) -> Self {
        Self { arena, offset }
    }

    /// Returns the destination arena.
    #[inline]
    pub const fn arena(self) -> LayoutArenaId {
        self.arena
    }

    /// Returns the arena-relative byte offset.
    #[inline]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Adds `delta` bytes to the current address.
    #[inline]
    pub fn checked_add(self, delta: usize) -> Option<Self> {
        self.offset.checked_add(delta).map(|offset| Self {
            arena: self.arena,
            offset,
        })
    }
}

/// One relocation site with its derived destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationSiteAddress {
    entry_index: usize,
    address: LayoutAddress,
}

impl RelocationSiteAddress {
    #[inline]
    fn new(entry_index: usize, address: LayoutAddress) -> Self {
        Self {
            entry_index,
            address,
        }
    }

    /// Returns the relocation entry index inside the relocation section.
    #[inline]
    pub const fn entry_index(self) -> usize {
        self.entry_index
    }

    /// Returns the derived address of the relocation site.
    #[inline]
    pub const fn address(self) -> LayoutAddress {
        self.address
    }
}

/// A derived address map for every module in one layout plan.
#[derive(Debug, Clone)]
pub struct LayoutAddressMap<K> {
    modules: BTreeMap<K, ModuleAddressMap>,
}

impl<K> Default for LayoutAddressMap<K> {
    #[inline]
    fn default() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }
}

/// A derived address map for one module.
#[derive(Debug, Clone, Default)]
pub struct ModuleAddressMap {
    sections: BTreeMap<ScannedSectionId, SectionPlacement>,
    relocation_sites: BTreeMap<ScannedSectionId, Box<[RelocationSiteAddress]>>,
}

impl<K> LayoutAddressMap<K>
where
    K: Ord,
{
    /// Creates an empty address map.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the derived address map for one module.
    #[inline]
    pub fn module(&self, key: &K) -> Option<&ModuleAddressMap> {
        self.modules.get(key)
    }

    /// Returns the derived section address for `key` and `id`.
    #[inline]
    pub fn section_address(&self, key: &K, id: ScannedSectionId) -> Option<LayoutAddress> {
        self.module(key)
            .and_then(|module| module.section_address(id))
    }

    /// Returns the placed section reference for `key` and `id`.
    #[inline]
    pub fn section_placement(&self, key: &K, id: ScannedSectionId) -> Option<SectionPlacement> {
        self.module(key)
            .and_then(|module| module.section_placement(id))
    }

    /// Returns the arena that hosts one placed section.
    #[inline]
    pub fn section_arena(&self, key: &K, id: ScannedSectionId) -> Option<LayoutArenaId> {
        self.module(key).and_then(|module| module.section_arena(id))
    }

    /// Returns the derived relocation-site address for one relocation entry.
    #[inline]
    pub fn relocation_site_address(
        &self,
        key: &K,
        relocation_section: ScannedSectionId,
        entry_index: usize,
    ) -> Option<LayoutAddress> {
        self.module(key)
            .and_then(|module| module.relocation_site_address(relocation_section, entry_index))
    }

    /// Inserts or replaces one module address map.
    #[inline]
    pub fn insert_module(&mut self, key: K, map: ModuleAddressMap) -> Option<ModuleAddressMap> {
        self.modules.insert(key, map)
    }
}

impl ModuleAddressMap {
    /// Creates an empty module address map.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn from_layout(
        layout: &ModuleLayout,
        section_metadata: &LayoutSectionMetadataArena,
        regions: &LayoutRegionArena,
    ) -> Self {
        let mut map = Self::new();

        for (scanned_section, section_id) in layout.section_entries() {
            let Some(section) = section_metadata.get(*section_id) else {
                continue;
            };
            let Some(region) = section.region() else {
                continue;
            };
            let Some(region_placement) = regions
                .get(region.region())
                .and_then(|layout_region| layout_region.placement())
            else {
                continue;
            };
            let Some(placement) = SectionPlacement::from_region(region_placement, region) else {
                continue;
            };
            map.sections.insert(*scanned_section, placement);
        }

        for (scanned_relocation_section, section_id) in layout.section_entries() {
            let Some(relocation_section) = section_metadata
                .get(*section_id)
                .and_then(LayoutSectionMetadata::retained_relocations)
            else {
                continue;
            };
            let Some(target_section) = relocation_section.target_section() else {
                continue;
            };
            let Some(base) = map
                .section_placement(target_section)
                .map(SectionPlacement::address)
            else {
                continue;
            };

            let sites = relocation_section
                .entries()
                .iter()
                .enumerate()
                .filter_map(|(entry_index, entry)| {
                    base.checked_add(entry.offset())
                        .map(|address| RelocationSiteAddress::new(entry_index, address))
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();

            map.relocation_sites
                .insert(*scanned_relocation_section, sites);
        }

        map
    }

    /// Returns the placed section reference for one section.
    #[inline]
    pub fn section_placement(&self, id: ScannedSectionId) -> Option<SectionPlacement> {
        self.sections.get(&id).copied()
    }

    /// Returns the derived section address for one section.
    #[inline]
    pub fn section_address(&self, id: ScannedSectionId) -> Option<LayoutAddress> {
        self.section_placement(id).map(SectionPlacement::address)
    }

    /// Returns the arena that hosts one placed section.
    #[inline]
    pub fn section_arena(&self, id: ScannedSectionId) -> Option<LayoutArenaId> {
        self.section_placement(id).map(SectionPlacement::arena)
    }

    /// Returns the derived relocation sites for one relocation section.
    #[inline]
    pub fn relocation_sites(
        &self,
        relocation_section: ScannedSectionId,
    ) -> Option<&[RelocationSiteAddress]> {
        self.relocation_sites
            .get(&relocation_section)
            .map(Box::as_ref)
    }

    /// Returns the derived relocation-site address for one relocation entry.
    #[inline]
    pub fn relocation_site_address(
        &self,
        relocation_section: ScannedSectionId,
        entry_index: usize,
    ) -> Option<LayoutAddress> {
        self.relocation_sites(relocation_section).and_then(|sites| {
            sites
                .iter()
                .find(|site| site.entry_index() == entry_index)
                .map(|site| site.address())
        })
    }
}
