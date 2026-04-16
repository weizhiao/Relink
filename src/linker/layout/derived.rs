use super::{
    arena::LayoutArenaId,
    section::{LayoutSectionArena, LayoutSectionData, LayoutSectionId, ModuleLayout},
};
use crate::{
    Result,
    elf::ElfRelType,
    image::{ModuleCapability, ScannedRelocationAddend},
};
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

/// One retained relocation site that needs repair after section reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutRelocationSiteRepair {
    entry_index: usize,
    original_address: usize,
    relocation_type: usize,
    symbol_index: usize,
    addend: ScannedRelocationAddend,
    address: LayoutAddress,
}

impl LayoutRelocationSiteRepair {
    #[inline]
    const fn new(
        entry_index: usize,
        original_address: usize,
        relocation_type: usize,
        symbol_index: usize,
        addend: ScannedRelocationAddend,
        address: LayoutAddress,
    ) -> Self {
        Self {
            entry_index,
            original_address,
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

    /// Returns the original relocation-site virtual address recorded by the retained entry.
    #[inline]
    pub const fn original_address(self) -> usize {
        self.original_address
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
    target_section: Option<LayoutSectionId>,
    symbol_table_section: Option<LayoutSectionId>,
    sites: Box<[LayoutRelocationSiteRepair]>,
}

impl LayoutRetainedRelocationRepair {
    fn new(
        target_section: Option<LayoutSectionId>,
        symbol_table_section: Option<LayoutSectionId>,
        sites: Box<[LayoutRelocationSiteRepair]>,
    ) -> Self {
        Self {
            target_section,
            symbol_table_section,
            sites,
        }
    }

    /// Returns the target section referenced by `sh_info`, when present.
    #[inline]
    pub const fn target_section(&self) -> Option<LayoutSectionId> {
        self.target_section
    }

    /// Returns the symbol table referenced by `sh_link`, when present.
    #[inline]
    pub const fn symbol_table_section(&self) -> Option<LayoutSectionId> {
        self.symbol_table_section
    }

    /// Returns the relocation-site repairs carried by this relocation section.
    #[inline]
    pub fn sites(&self) -> &[LayoutRelocationSiteRepair] {
        &self.sites
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleLayoutDerived {
    relocation_repairs: BTreeMap<LayoutSectionId, LayoutRetainedRelocationRepair>,
}

impl Default for ModuleLayoutDerived {
    #[inline]
    fn default() -> Self {
        Self {
            relocation_repairs: BTreeMap::new(),
        }
    }
}

impl ModuleLayoutDerived {
    #[inline]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(super) fn from_layout(
        layout: &ModuleLayout,
        capability: ModuleCapability,
        sections: &LayoutSectionArena,
    ) -> Result<Self> {
        let mut derived = Self::new();
        if !capability.supports_reorder_repair() {
            return Ok(derived);
        }

        for section_id in layout.relocation_sections().iter().copied() {
            let section = sections
                .get(section_id)
                .expect("module layout referenced missing relocation section metadata");
            let Some(LayoutSectionData::Bytes(bytes)) = sections.data(section_id) else {
                return Err(crate::custom_error(
                    "retained relocation section must be backed by materialized bytes",
                ));
            };
            let entries = bytes.try_cast_slice::<ElfRelType>().ok_or_else(|| {
                crate::custom_error(
                    "retained relocation section bytes do not match relocation entries",
                )
            })?;

            let mut sites = Vec::with_capacity(entries.len());
            let target_section = section.info_section();

            for (entry_index, entry) in entries.iter().enumerate() {
                let Some(address) =
                    resolve_original_address(layout, sections, target_section, entry.r_offset())
                else {
                    continue;
                };
                #[cfg(any(target_arch = "x86", target_arch = "arm"))]
                let addend = ScannedRelocationAddend::Implicit;
                #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
                let addend = ScannedRelocationAddend::Explicit(entry.r_addend(0));
                sites.push(LayoutRelocationSiteRepair::new(
                    entry_index,
                    entry.r_offset(),
                    entry.r_type(),
                    entry.r_symbol(),
                    addend,
                    address,
                ));
            }

            derived.relocation_repairs.insert(
                section_id,
                LayoutRetainedRelocationRepair::new(
                    section.info_section(),
                    section.linked_section(),
                    sites.into_boxed_slice(),
                ),
            );
        }

        Ok(derived)
    }

    #[inline]
    pub(crate) fn relocation_repairs(
        &self,
    ) -> impl Iterator<Item = (&LayoutSectionId, &LayoutRetainedRelocationRepair)> {
        self.relocation_repairs.iter()
    }
}

fn resolve_original_address(
    layout: &ModuleLayout,
    sections: &LayoutSectionArena,
    target_section: Option<LayoutSectionId>,
    original_address: usize,
) -> Option<LayoutAddress> {
    if let Some(section_id) = target_section {
        return resolve_original_address_in_section(sections, section_id, original_address);
    }

    layout
        .alloc_sections()
        .iter()
        .copied()
        .find_map(|section_id| {
            resolve_original_address_in_section(sections, section_id, original_address)
        })
}

fn resolve_original_address_in_section(
    sections: &LayoutSectionArena,
    section_id: LayoutSectionId,
    original_address: usize,
) -> Option<LayoutAddress> {
    let placement = sections.placement(section_id)?;
    let metadata = sections.get(section_id)?;
    let delta = original_address.checked_sub(metadata.original_address())?;
    (delta < metadata.size())
        .then(|| LayoutAddress::new(placement.arena(), placement.offset() + delta))
}
