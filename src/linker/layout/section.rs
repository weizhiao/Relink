use super::{
    address::LayoutAddress,
    arena::{LayoutArenaId, LayoutMemoryClass},
    region::{LayoutRegionPlacement, SectionRegionPlacement},
};
use crate::{
    entity::{EntityArena, entity_ref},
    image::{
        ScannedDylib, ScannedMemoryData, ScannedMemoryKind, ScannedRelocation,
        ScannedRelocationFormat, ScannedRelocationSection, ScannedSection, ScannedSectionId,
    },
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// A stable id for one section metadata record stored in [`super::MemoryLayoutPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutSectionId(usize);
entity_ref!(LayoutSectionId);

/// A stable id for one materialized section-data record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutSectionDataId(usize);
entity_ref!(LayoutSectionDataId);

/// The derived physical placement of one section inside a physical arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionPlacement {
    arena: LayoutArenaId,
    offset: usize,
    size: usize,
}

impl SectionPlacement {
    /// Creates a new section placement inside a physical arena.
    #[inline]
    pub const fn new(arena: LayoutArenaId, offset: usize, size: usize) -> Self {
        Self {
            arena,
            offset,
            size,
        }
    }

    /// Creates a physical section placement from region mappings.
    #[inline]
    pub fn from_region(
        region: LayoutRegionPlacement,
        section: SectionRegionPlacement,
    ) -> Option<Self> {
        region
            .offset()
            .checked_add(section.offset())
            .map(|offset| Self::new(region.arena(), offset, section.size()))
    }

    /// Returns the arena that owns the placed section.
    #[inline]
    pub const fn arena(self) -> LayoutArenaId {
        self.arena
    }

    /// Returns the byte offset inside the arena.
    #[inline]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Returns the section size in bytes.
    #[inline]
    pub const fn size(self) -> usize {
        self.size
    }

    /// Returns the start address of the placed section.
    #[inline]
    pub const fn address(self) -> LayoutAddress {
        LayoutAddress::new(self.arena, self.offset)
    }
}

/// The original source that produced one planned section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutSectionSource {
    /// The section maps directly to one scanned section.
    Scanned(ScannedSectionId),
    /// The section was synthesized by a later planning pass.
    Synthetic(Box<str>),
}

/// The retained relocation metadata tracked for one relocation section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutRetainedRelocationSection {
    format: ScannedRelocationFormat,
    target_section: Option<ScannedSectionId>,
    symbol_table_section: Option<ScannedSectionId>,
    entries: Box<[ScannedRelocation]>,
}

impl LayoutRetainedRelocationSection {
    fn from_scanned(section: ScannedRelocationSection) -> Self {
        Self {
            format: section.format(),
            target_section: section.target_section(),
            symbol_table_section: section.symbol_table_section(),
            entries: section.entries().to_vec().into_boxed_slice(),
        }
    }

    /// Returns whether the relocation section uses `REL` or `RELA`.
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

    /// Returns the normalized relocation entries.
    #[inline]
    pub fn entries(&self) -> &[ScannedRelocation] {
        &self.entries
    }

    /// Returns the number of relocation entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the relocation section is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The immutable metadata tracked for one planned section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSectionMetadata {
    source: LayoutSectionSource,
    name: Box<str>,
    memory_class: LayoutMemoryClass,
    original_address: usize,
    original_file_offset: usize,
    size: usize,
    alignment: usize,
    zero_fill: bool,
    data: Option<LayoutSectionDataId>,
    region: Option<SectionRegionPlacement>,
    retained_relocations: Option<LayoutRetainedRelocationSection>,
}

impl LayoutSectionMetadata {
    /// Creates a new section metadata record.
    #[inline]
    pub fn new(
        source: LayoutSectionSource,
        name: impl Into<Box<str>>,
        memory_class: LayoutMemoryClass,
        original_address: usize,
        original_file_offset: usize,
        size: usize,
        alignment: usize,
        zero_fill: bool,
    ) -> Self {
        Self {
            source,
            name: name.into(),
            memory_class,
            original_address,
            original_file_offset,
            size,
            alignment: alignment.max(1),
            zero_fill,
            data: None,
            region: None,
            retained_relocations: None,
        }
    }

    pub(super) fn from_scanned(section: ScannedSection<'_>) -> Self {
        Self::new(
            LayoutSectionSource::Scanned(section.id()),
            section.name(),
            classify_section(section),
            section.address(),
            section.file_offset(),
            section.size(),
            section.alignment(),
            section.is_nobits(),
        )
    }

    pub(super) fn from_relocation(section: ScannedRelocationSection) -> Self {
        Self {
            source: LayoutSectionSource::Scanned(section.id()),
            name: section.name().into(),
            memory_class: LayoutMemoryClass::RelocationReadOnlyData,
            original_address: 0,
            original_file_offset: section.file_offset(),
            size: section.size(),
            alignment: section.alignment(),
            zero_fill: false,
            data: None,
            region: None,
            retained_relocations: Some(LayoutRetainedRelocationSection::from_scanned(section)),
        }
    }

    /// Returns the original source that produced the section.
    #[inline]
    pub fn source(&self) -> &LayoutSectionSource {
        &self.source
    }

    /// Returns the original scanned section id, when this section came from scan.
    #[inline]
    pub fn scanned_section(&self) -> Option<ScannedSectionId> {
        match self.source {
            LayoutSectionSource::Scanned(id) => Some(id),
            LayoutSectionSource::Synthetic(_) => None,
        }
    }

    /// Returns the section name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the section memory class.
    #[inline]
    pub const fn memory_class(&self) -> LayoutMemoryClass {
        self.memory_class
    }

    /// Returns whether this metadata record describes a loadable section.
    #[inline]
    pub const fn is_allocated(&self) -> bool {
        self.retained_relocations.is_none()
    }

    /// Returns whether this metadata record describes a retained relocation section.
    #[inline]
    pub const fn is_relocation(&self) -> bool {
        self.retained_relocations.is_some()
    }

    /// Returns the original ELF virtual address.
    #[inline]
    pub const fn original_address(&self) -> usize {
        self.original_address
    }

    /// Returns the original ELF file offset.
    #[inline]
    pub const fn original_file_offset(&self) -> usize {
        self.original_file_offset
    }

    /// Returns the logical size in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the alignment in bytes.
    #[inline]
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Returns whether the section is zero-fill.
    #[inline]
    pub const fn zero_fill(&self) -> bool {
        self.zero_fill
    }

    /// Returns the materialized data id, when section bytes have been loaded.
    #[inline]
    pub const fn data(&self) -> Option<LayoutSectionDataId> {
        self.data
    }

    /// Returns the logical region assignment of the section, when present.
    #[inline]
    pub const fn region(&self) -> Option<SectionRegionPlacement> {
        self.region
    }

    /// Returns the retained relocation metadata for this section, when present.
    #[inline]
    pub fn retained_relocations(&self) -> Option<&LayoutRetainedRelocationSection> {
        self.retained_relocations.as_ref()
    }

    #[inline]
    pub(super) fn set_data(&mut self, data: LayoutSectionDataId) {
        self.data = Some(data);
    }

    #[inline]
    pub(super) fn set_region(&mut self, region: SectionRegionPlacement) {
        self.region = Some(region);
    }

    #[inline]
    pub(super) fn clear_region(&mut self) -> Option<SectionRegionPlacement> {
        self.region.take()
    }
}

/// A dense arena of section metadata records.
#[derive(Debug, Clone, Default)]
pub struct LayoutSectionMetadataArena {
    sections: EntityArena<LayoutSectionId, LayoutSectionMetadata>,
}

impl LayoutSectionMetadataArena {
    /// Creates an empty metadata arena.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn insert(&mut self, section: LayoutSectionMetadata) -> LayoutSectionId {
        self.sections.push(section)
    }

    /// Returns one section metadata record by id.
    #[inline]
    pub fn get(&self, id: LayoutSectionId) -> Option<&LayoutSectionMetadata> {
        self.sections.get(id)
    }

    /// Returns one section metadata record by id mutably.
    #[inline]
    pub fn get_mut(&mut self, id: LayoutSectionId) -> Option<&mut LayoutSectionMetadata> {
        self.sections.get_mut(id)
    }

    /// Iterates over section ids and metadata records together.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (LayoutSectionId, &LayoutSectionMetadata)> {
        self.sections.iter()
    }

    /// Iterates over section ids and metadata records together mutably.
    #[inline]
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (LayoutSectionId, &mut LayoutSectionMetadata)> {
        self.sections.iter_mut()
    }
}

/// The materialized data owned by one section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutSectionData {
    /// Materialized file-backed bytes.
    Bytes(Box<[u8]>),
    /// Logical zero-fill storage.
    ZeroFill { size: usize },
}

impl LayoutSectionData {
    /// Returns the logical size in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::ZeroFill { size } => *size,
        }
    }

    /// Returns whether the data length is zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the materialized bytes when the section is file-backed.
    #[inline]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::ZeroFill { .. } => None,
        }
    }
}

/// A dense arena of materialized section-data records.
#[derive(Debug, Clone, Default)]
pub struct LayoutSectionDataArena {
    data: EntityArena<LayoutSectionDataId, LayoutSectionData>,
}

impl LayoutSectionDataArena {
    /// Creates an empty section-data arena.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn push(&mut self, data: ScannedMemoryData) -> LayoutSectionDataId {
        let record = match data {
            ScannedMemoryData::Bytes(bytes) => LayoutSectionData::Bytes(bytes),
            ScannedMemoryData::ZeroFill { size } => LayoutSectionData::ZeroFill { size },
        };
        self.data.push(record)
    }

    /// Returns one materialized section-data record by id.
    #[inline]
    pub fn get(&self, id: LayoutSectionDataId) -> Option<&LayoutSectionData> {
        self.data.get(id)
    }
}

/// One module's logical section view inside the layout plan.
#[derive(Debug, Clone, Default)]
pub struct ModuleLayout {
    alloc_sections: Box<[LayoutSectionId]>,
    scanned_sections: BTreeMap<ScannedSectionId, LayoutSectionId>,
}

impl ModuleLayout {
    /// Creates an empty module layout.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates one module layout from explicit scanned-section mappings.
    pub fn from_sections<I>(sections: I) -> Self
    where
        I: IntoIterator<Item = (ScannedSectionId, LayoutSectionId)>,
    {
        let mut ordered = Vec::new();
        let mut scanned_sections = BTreeMap::new();

        for (scanned_section, section_id) in sections {
            ordered.push(section_id);
            scanned_sections.insert(scanned_section, section_id);
        }

        Self {
            alloc_sections: ordered.into_boxed_slice(),
            scanned_sections,
        }
    }

    /// Builds a section-granularity layout seed from a scanned module.
    pub fn from_scanned<D>(
        module: &ScannedDylib<D>,
        section_metadata: &mut LayoutSectionMetadataArena,
    ) -> Self
    where
        D: 'static,
    {
        Self::from_sections(module.alloc_sections().map(|section| {
            let section_id = section_metadata.insert(LayoutSectionMetadata::from_scanned(section));
            (section.id(), section_id)
        }))
    }

    /// Returns the allocatable section ids that participate in default packing.
    #[inline]
    pub fn alloc_sections(&self) -> &[LayoutSectionId] {
        &self.alloc_sections
    }

    /// Returns one section id by its original scanned section id.
    #[inline]
    pub fn section_id(&self, section: ScannedSectionId) -> Option<LayoutSectionId> {
        self.scanned_sections.get(&section).copied()
    }

    #[inline]
    pub(super) fn insert_section(
        &mut self,
        scanned_section: ScannedSectionId,
        section_id: LayoutSectionId,
    ) {
        self.scanned_sections.insert(scanned_section, section_id);
    }

    /// Iterates over every known section mapping for this module.
    #[inline]
    pub fn section_entries(&self) -> impl Iterator<Item = (&ScannedSectionId, &LayoutSectionId)> {
        self.scanned_sections.iter()
    }
}

#[inline]
fn classify_section(section: ScannedSection<'_>) -> LayoutMemoryClass {
    match section
        .memory_kind()
        .expect("section-granularity layout seeding requires alloc sections")
    {
        ScannedMemoryKind::Code => LayoutMemoryClass::Code,
        ScannedMemoryKind::ReadOnlyData => LayoutMemoryClass::ReadOnlyData,
        ScannedMemoryKind::WritableData => LayoutMemoryClass::WritableData,
        ScannedMemoryKind::ThreadLocalData => LayoutMemoryClass::ThreadLocalData,
    }
}
