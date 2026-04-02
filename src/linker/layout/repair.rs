use super::{
    address::{LayoutAddress, ModuleAddressMap},
    section::{LayoutSectionMetadata, LayoutSectionMetadataArena, ModuleLayout},
};
use crate::image::{ScannedRelocationAddend, ScannedRelocationFormat, ScannedSectionId};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// The current reorder-repair state for one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutRepairStatus {
    /// No physical section layout is currently active, so no repair is needed yet.
    NotNeeded,
    /// The module has been physically laid out, but retained relocations are missing.
    MissingRetainedRelocations,
    /// The core has enough retained relocation inputs to drive reorder repair.
    Ready,
}

/// One section-base repair entry derived from a physical layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutSectionRepair {
    original_address: usize,
    address: LayoutAddress,
}

impl LayoutSectionRepair {
    #[inline]
    const fn new(original_address: usize, address: LayoutAddress) -> Self {
        Self {
            original_address,
            address,
        }
    }

    /// Returns the original ELF section address.
    #[inline]
    pub const fn original_address(self) -> usize {
        self.original_address
    }

    /// Returns the new derived section address inside the layout plan.
    #[inline]
    pub const fn address(self) -> LayoutAddress {
        self.address
    }
}

/// One retained relocation site that needs repair after section reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutRelocationSiteRepair {
    entry_index: usize,
    original_offset: usize,
    relocation_type: usize,
    symbol_index: usize,
    addend: ScannedRelocationAddend,
    address: LayoutAddress,
}

impl LayoutRelocationSiteRepair {
    #[inline]
    const fn new(
        entry_index: usize,
        original_offset: usize,
        relocation_type: usize,
        symbol_index: usize,
        addend: ScannedRelocationAddend,
        address: LayoutAddress,
    ) -> Self {
        Self {
            entry_index,
            original_offset,
            relocation_type,
            symbol_index,
            addend,
            address,
        }
    }

    /// Returns the relocation entry index inside the retained relocation section.
    #[inline]
    pub const fn entry_index(self) -> usize {
        self.entry_index
    }

    /// Returns the original section-relative relocation-site offset.
    #[inline]
    pub const fn original_offset(self) -> usize {
        self.original_offset
    }

    /// Returns the relocation type that must be replayed.
    #[inline]
    pub const fn relocation_type(self) -> usize {
        self.relocation_type
    }

    /// Returns the referenced symbol-table index.
    #[inline]
    pub const fn symbol_index(self) -> usize {
        self.symbol_index
    }

    /// Returns the retained addend representation.
    #[inline]
    pub const fn addend(self) -> ScannedRelocationAddend {
        self.addend
    }

    /// Returns the derived destination address of the relocation site.
    #[inline]
    pub const fn address(self) -> LayoutAddress {
        self.address
    }
}

/// The repair worklist derived from one retained relocation section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutRetainedRelocationRepair {
    format: ScannedRelocationFormat,
    target_section: Option<ScannedSectionId>,
    symbol_table_section: Option<ScannedSectionId>,
    sites: Box<[LayoutRelocationSiteRepair]>,
}

impl LayoutRetainedRelocationRepair {
    fn new(
        format: ScannedRelocationFormat,
        target_section: Option<ScannedSectionId>,
        symbol_table_section: Option<ScannedSectionId>,
        sites: Box<[LayoutRelocationSiteRepair]>,
    ) -> Self {
        Self {
            format,
            target_section,
            symbol_table_section,
            sites,
        }
    }

    /// Returns whether the retained relocation section uses `REL` or `RELA`.
    #[inline]
    pub const fn format(&self) -> ScannedRelocationFormat {
        self.format
    }

    /// Returns the target section referenced by `sh_info`, when present.
    #[inline]
    pub const fn target_section(&self) -> Option<ScannedSectionId> {
        self.target_section
    }

    /// Returns the symbol table referenced by `sh_link`, when present.
    #[inline]
    pub const fn symbol_table_section(&self) -> Option<ScannedSectionId> {
        self.symbol_table_section
    }

    /// Returns the relocation-site repairs carried by this relocation section.
    #[inline]
    pub fn sites(&self) -> &[LayoutRelocationSiteRepair] {
        &self.sites
    }
}

/// The core reorder-repair plan for one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleLayoutRepair {
    status: LayoutRepairStatus,
    section_repairs: BTreeMap<ScannedSectionId, LayoutSectionRepair>,
    relocation_repairs: BTreeMap<ScannedSectionId, LayoutRetainedRelocationRepair>,
}

impl Default for ModuleLayoutRepair {
    #[inline]
    fn default() -> Self {
        Self {
            status: LayoutRepairStatus::NotNeeded,
            section_repairs: BTreeMap::new(),
            relocation_repairs: BTreeMap::new(),
        }
    }
}

impl ModuleLayoutRepair {
    /// Creates an empty module repair plan.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn from_layout(
        layout: &ModuleLayout,
        section_metadata: &LayoutSectionMetadataArena,
        addresses: &ModuleAddressMap,
    ) -> Self {
        let mut repair = Self::new();
        let mut has_physical_layout = false;
        let mut has_retained_relocations = false;

        for (scanned_section, section_id) in layout.section_entries() {
            let Some(section) = section_metadata.get(*section_id) else {
                continue;
            };

            if section.retained_relocations().is_some() {
                has_retained_relocations = true;
            }

            if !section.is_allocated() {
                continue;
            }

            let Some(address) = addresses.section_address(*scanned_section) else {
                continue;
            };

            has_physical_layout = true;
            repair.section_repairs.insert(
                *scanned_section,
                LayoutSectionRepair::new(section.original_address(), address),
            );
        }

        for (scanned_relocation_section, section_id) in layout.section_entries() {
            let Some(relocation_section) = section_metadata
                .get(*section_id)
                .and_then(LayoutSectionMetadata::retained_relocations)
            else {
                continue;
            };

            let mut sites = Vec::with_capacity(relocation_section.entries().len());
            for (entry_index, entry) in relocation_section.entries().iter().enumerate() {
                let Some(address) =
                    addresses.relocation_site_address(*scanned_relocation_section, entry_index)
                else {
                    continue;
                };
                sites.push(LayoutRelocationSiteRepair::new(
                    entry_index,
                    entry.offset(),
                    entry.relocation_type(),
                    entry.symbol_index(),
                    entry.addend(),
                    address,
                ));
            }

            repair.relocation_repairs.insert(
                *scanned_relocation_section,
                LayoutRetainedRelocationRepair::new(
                    relocation_section.format(),
                    relocation_section.target_section(),
                    relocation_section.symbol_table_section(),
                    sites.into_boxed_slice(),
                ),
            );
        }

        repair.status = if !has_physical_layout {
            LayoutRepairStatus::NotNeeded
        } else if has_retained_relocations {
            LayoutRepairStatus::Ready
        } else {
            LayoutRepairStatus::MissingRetainedRelocations
        };

        repair
    }

    /// Returns the current reorder-repair state for the module.
    #[inline]
    pub const fn status(&self) -> LayoutRepairStatus {
        self.status
    }

    /// Returns the section-base repair entry for one scanned section.
    #[inline]
    pub fn section_repair(&self, section: ScannedSectionId) -> Option<&LayoutSectionRepair> {
        self.section_repairs.get(&section)
    }

    /// Iterates over section-base repair entries.
    #[inline]
    pub fn section_repairs(
        &self,
    ) -> impl Iterator<Item = (&ScannedSectionId, &LayoutSectionRepair)> {
        self.section_repairs.iter()
    }

    /// Returns the retained-relocation repair for one relocation section.
    #[inline]
    pub fn relocation_repair(
        &self,
        relocation_section: ScannedSectionId,
    ) -> Option<&LayoutRetainedRelocationRepair> {
        self.relocation_repairs.get(&relocation_section)
    }

    /// Iterates over retained-relocation repairs.
    #[inline]
    pub fn relocation_repairs(
        &self,
    ) -> impl Iterator<Item = (&ScannedSectionId, &LayoutRetainedRelocationRepair)> {
        self.relocation_repairs.iter()
    }
}

/// The core reorder-repair plans derived for every module in one layout plan.
#[derive(Debug, Clone)]
pub struct LayoutRepairPlan<K> {
    modules: BTreeMap<K, ModuleLayoutRepair>,
}

impl<K> Default for LayoutRepairPlan<K> {
    #[inline]
    fn default() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }
}

impl<K> LayoutRepairPlan<K>
where
    K: Ord,
{
    /// Creates an empty repair plan set.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the module repair plan for one module.
    #[inline]
    pub fn module(&self, key: &K) -> Option<&ModuleLayoutRepair> {
        self.modules.get(key)
    }

    /// Inserts or replaces one module repair plan.
    #[inline]
    pub fn insert_module(
        &mut self,
        key: K,
        repair: ModuleLayoutRepair,
    ) -> Option<ModuleLayoutRepair> {
        self.modules.insert(key, repair)
    }
}
