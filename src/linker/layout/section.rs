use super::{
    arena::{LayoutArenaId, LayoutMemoryClass},
    derived::LayoutAddress,
};
use crate::{
    AlignedBytes,
    entity::{PrimaryMap, entity_ref},
    image::{ScannedDylib, ScannedSection, ScannedSectionId},
    linker::plan::LinkModuleId,
};
use alloc::{boxed::Box, vec::Vec};

/// A stable id for one section metadata record stored in [`super::MemoryLayoutPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutSectionId(usize);
entity_ref!(LayoutSectionId);

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

/// The logical kind of one section carried by the layout plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutSectionKind {
    /// One allocatable section with its final memory class.
    Allocated(LayoutMemoryClass),
    /// One retained relocation section kept for reorder repair.
    RetainedRelocation,
    /// One non-alloc, non-relocation section kept only as metadata.
    NonAllocated,
}

/// The immutable metadata tracked for one planned section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSectionMetadata {
    scanned_section: ScannedSectionId,
    name: Box<str>,
    kind: LayoutSectionKind,
    linked_section: Option<LayoutSectionId>,
    info_section: Option<LayoutSectionId>,
    original_address: usize,
    original_file_offset: usize,
    size: usize,
    alignment: usize,
    zero_fill: bool,
}

impl LayoutSectionMetadata {
    /// Creates a new section metadata record.
    #[inline]
    pub fn new<T, U>(
        scanned_section: ScannedSectionId,
        name: impl Into<Box<str>>,
        kind: LayoutSectionKind,
        linked_section: Option<T>,
        info_section: Option<U>,
        original_address: usize,
        original_file_offset: usize,
        size: usize,
        alignment: usize,
        zero_fill: bool,
    ) -> Self
    where
        T: Into<LayoutSectionId>,
        U: Into<LayoutSectionId>,
    {
        Self {
            scanned_section,
            name: name.into(),
            kind,
            linked_section: linked_section.map(Into::into),
            info_section: info_section.map(Into::into),
            original_address,
            original_file_offset,
            size,
            alignment: alignment.max(1),
            zero_fill,
        }
    }

    pub(super) fn from_scanned(section: ScannedSection<'_>) -> Self {
        let kind = match section.section_type() {
            crate::elf::ElfSectionType::REL | crate::elf::ElfSectionType::RELA => {
                LayoutSectionKind::RetainedRelocation
            }
            _ if !section.is_allocated() => LayoutSectionKind::NonAllocated,
            _ => {
                let class = if section.is_tls() {
                    LayoutMemoryClass::ThreadLocalData
                } else if section.is_executable() {
                    LayoutMemoryClass::Code
                } else if section.is_writable() {
                    LayoutMemoryClass::WritableData
                } else {
                    LayoutMemoryClass::ReadOnlyData
                };
                LayoutSectionKind::Allocated(class)
            }
        };

        Self::new(
            section.id(),
            section.name(),
            kind,
            None::<LayoutSectionId>,
            None::<LayoutSectionId>,
            section.address(),
            section.file_offset(),
            section.size(),
            section.alignment(),
            section.is_nobits(),
        )
    }

    /// Returns the original scanned section id.
    #[inline]
    pub const fn scanned_section(&self) -> ScannedSectionId {
        self.scanned_section
    }

    /// Returns the section name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the normalized `sh_link` section reference, when present.
    #[inline]
    pub const fn linked_section(&self) -> Option<LayoutSectionId> {
        self.linked_section
    }

    /// Returns the normalized `sh_info` section reference, when present.
    #[inline]
    pub const fn info_section(&self) -> Option<LayoutSectionId> {
        self.info_section
    }

    /// Returns the logical kind of this section.
    #[inline]
    pub const fn kind(&self) -> LayoutSectionKind {
        self.kind
    }

    #[inline]
    pub(super) fn set_links(
        &mut self,
        linked_section: Option<LayoutSectionId>,
        info_section: Option<LayoutSectionId>,
    ) {
        self.linked_section = linked_section;
        self.info_section = info_section;
    }

    /// Returns whether this metadata record describes a loadable section.
    #[inline]
    pub const fn is_allocated(&self) -> bool {
        matches!(self.kind, LayoutSectionKind::Allocated(_))
    }

    /// Returns whether this metadata record describes a retained relocation section.
    #[inline]
    pub const fn is_relocation(&self) -> bool {
        matches!(self.kind, LayoutSectionKind::RetainedRelocation)
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
}

/// The materialized data owned by one section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutSectionData {
    /// Materialized file-backed bytes.
    Bytes(AlignedBytes),
    /// Logical zero-fill storage.
    ZeroFill { size: usize },
}

impl LayoutSectionData {
    /// Returns the materialized bytes when the section is file-backed.
    #[inline]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.as_ref()),
            Self::ZeroFill { .. } => None,
        }
    }

    /// Returns mutable bytes, materializing zero-fill storage when needed.
    pub fn ensure_bytes_mut(&mut self) -> &mut [u8] {
        if let Self::ZeroFill { size } = *self {
            *self = Self::Bytes(AlignedBytes::with_len(size).expect("failed to allocate bytes"));
        }

        match self {
            Self::Bytes(bytes) => bytes.as_mut(),
            Self::ZeroFill { .. } => unreachable!(),
        }
    }
}

/// One complete section record tracked by the layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSectionRecord {
    owner: LinkModuleId,
    metadata: LayoutSectionMetadata,
    data: Option<LayoutSectionData>,
    override_data: bool,
    placement: Option<SectionPlacement>,
}

impl LayoutSectionRecord {
    #[inline]
    pub fn new(owner: LinkModuleId, metadata: LayoutSectionMetadata) -> Self {
        Self {
            owner,
            metadata,
            data: None,
            override_data: false,
            placement: None,
        }
    }

    /// Returns the owner module of this section.
    #[inline]
    pub const fn owner(&self) -> LinkModuleId {
        self.owner
    }

    /// Returns the immutable metadata of this section.
    #[inline]
    pub fn metadata(&self) -> &LayoutSectionMetadata {
        &self.metadata
    }

    /// Returns the immutable metadata of this section mutably.
    #[inline]
    pub fn metadata_mut(&mut self) -> &mut LayoutSectionMetadata {
        &mut self.metadata
    }

    /// Returns the materialized data of this section, when present.
    #[inline]
    pub fn data(&self) -> Option<&LayoutSectionData> {
        self.data.as_ref()
    }

    /// Returns the materialized data of this section mutably, when present.
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut LayoutSectionData> {
        self.data.as_mut()
    }

    #[inline]
    fn install_data(&mut self, data: LayoutSectionData) {
        if self.data.is_none() {
            self.data = Some(data);
        }
    }

    /// Returns whether installed data should override the original bytes during
    /// whole-DSO materialization.
    #[inline]
    pub const fn overrides_original_data(&self) -> bool {
        self.override_data
    }

    #[inline]
    fn mark_data_override(&mut self) {
        self.override_data = true;
    }

    /// Returns the concrete arena placement of this section, when present.
    #[inline]
    pub fn placement(&self) -> Option<SectionPlacement> {
        self.placement
    }

    #[inline]
    fn set_placement(&mut self, placement: SectionPlacement) {
        self.placement = Some(placement);
    }

    #[inline]
    fn clear_placement(&mut self) -> Option<SectionPlacement> {
        self.placement.take()
    }
}

/// A dense arena of section records.
#[derive(Debug, Clone, Default)]
pub struct LayoutSectionArena {
    sections: PrimaryMap<LayoutSectionId, LayoutSectionRecord>,
}

impl LayoutSectionArena {
    /// Creates an empty section arena.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn insert(
        &mut self,
        owner: LinkModuleId,
        metadata: LayoutSectionMetadata,
    ) -> LayoutSectionId {
        self.sections
            .push(LayoutSectionRecord::new(owner, metadata))
    }

    /// Returns one section record by id.
    #[inline]
    pub fn record(&self, id: LayoutSectionId) -> Option<&LayoutSectionRecord> {
        self.sections.get(id)
    }

    /// Returns one section record by id mutably.
    #[inline]
    pub fn record_mut(&mut self, id: LayoutSectionId) -> Option<&mut LayoutSectionRecord> {
        self.sections.get_mut(id)
    }

    /// Returns one section metadata record by id.
    #[inline]
    pub fn get(&self, id: LayoutSectionId) -> Option<&LayoutSectionMetadata> {
        self.record(id).map(LayoutSectionRecord::metadata)
    }

    /// Returns the owner module of one section.
    #[inline]
    pub fn owner(&self, id: LayoutSectionId) -> Option<LinkModuleId> {
        self.record(id).map(LayoutSectionRecord::owner)
    }

    /// Returns one section metadata record by id mutably.
    #[inline]
    pub fn get_mut(&mut self, id: LayoutSectionId) -> Option<&mut LayoutSectionMetadata> {
        self.record_mut(id).map(LayoutSectionRecord::metadata_mut)
    }

    /// Iterates over section ids and section records together.
    #[inline]
    pub fn iter_records(&self) -> impl Iterator<Item = (LayoutSectionId, &LayoutSectionRecord)> {
        self.sections.iter()
    }

    /// Iterates over section ids and section records together mutably.
    #[inline]
    pub fn iter_records_mut(
        &mut self,
    ) -> impl Iterator<Item = (LayoutSectionId, &mut LayoutSectionRecord)> {
        self.sections.iter_mut()
    }

    /// Iterates over section ids and metadata records together.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (LayoutSectionId, &LayoutSectionMetadata)> {
        self.iter_records()
            .map(|(id, record)| (id, record.metadata()))
    }

    /// Iterates over section ids and metadata records together mutably.
    #[inline]
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (LayoutSectionId, &mut LayoutSectionMetadata)> {
        self.iter_records_mut()
            .map(|(id, record)| (id, record.metadata_mut()))
    }

    /// Returns one materialized section-data record by id.
    #[inline]
    pub fn data(&self, id: LayoutSectionId) -> Option<&LayoutSectionData> {
        self.record(id).and_then(LayoutSectionRecord::data)
    }

    /// Returns one materialized section-data record by id mutably.
    #[inline]
    pub fn data_mut(&mut self, id: LayoutSectionId) -> Option<&mut LayoutSectionData> {
        self.record_mut(id).and_then(LayoutSectionRecord::data_mut)
    }

    #[inline]
    pub(crate) fn overrides_original_data(&self, section: LayoutSectionId) -> bool {
        self.record(section)
            .is_some_and(LayoutSectionRecord::overrides_original_data)
    }

    #[inline]
    pub(crate) fn push_scanned(
        &mut self,
        section: LayoutSectionId,
        bytes: AlignedBytes,
    ) -> Option<LayoutSectionId> {
        self.install_data(section, LayoutSectionData::Bytes(bytes))
    }

    #[inline]
    pub(crate) fn install_data(
        &mut self,
        section: LayoutSectionId,
        data: LayoutSectionData,
    ) -> Option<LayoutSectionId> {
        let record = self.record_mut(section)?;
        record.install_data(data);
        Some(section)
    }

    #[inline]
    pub(crate) fn mark_data_override(&mut self, section: LayoutSectionId) -> Option<()> {
        let record = self.record_mut(section)?;
        record.mark_data_override();
        Some(())
    }

    /// Returns the concrete arena placement of one section, when present.
    #[inline]
    pub fn placement(&self, id: LayoutSectionId) -> Option<SectionPlacement> {
        self.record(id).and_then(LayoutSectionRecord::placement)
    }

    #[inline]
    pub(crate) fn set_placement(
        &mut self,
        section: LayoutSectionId,
        placement: SectionPlacement,
    ) -> bool {
        let Some(record) = self.record_mut(section) else {
            return false;
        };
        record.set_placement(placement);
        true
    }

    #[inline]
    pub(crate) fn clear_placement(&mut self, section: LayoutSectionId) -> Option<SectionPlacement> {
        self.record_mut(section)
            .and_then(LayoutSectionRecord::clear_placement)
    }

    #[inline]
    pub(crate) fn clear_placements(&mut self) {
        for (_, record) in self.iter_records_mut() {
            let _ = record.clear_placement();
        }
    }

    #[inline]
    pub(crate) fn has_any_placements(&self) -> bool {
        self.iter_records()
            .any(|(_, record)| record.placement().is_some())
    }
}

/// One module's logical section view inside the layout plan.
#[derive(Debug, Clone, Default)]
pub struct ModuleLayout {
    sections: Box<[LayoutSectionId]>,
    scanned_sources: Box<[Option<ScannedSectionId>]>,
    alloc_sections: Box<[LayoutSectionId]>,
    relocation_sections: Box<[LayoutSectionId]>,
}

impl ModuleLayout {
    /// Creates an empty module layout.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates one module layout from explicit scanned-section mappings.
    pub fn from_sections<I>(sections: I, arena: &LayoutSectionArena) -> Self
    where
        I: IntoIterator<Item = (ScannedSectionId, LayoutSectionId)>,
    {
        let mut ordered = Vec::new();
        let mut scanned_sources = Vec::new();
        let mut alloc_sections = Vec::new();
        let mut relocation_sections = Vec::new();

        for (scanned_section, section_id) in sections {
            ordered.push(section_id);
            scanned_sources.push(Some(scanned_section));

            if let Some(section) = arena.get(section_id) {
                if section.is_allocated() {
                    alloc_sections.push(section_id);
                }
                if section.is_relocation() {
                    relocation_sections.push(section_id);
                }
            }
        }

        Self {
            sections: ordered.into_boxed_slice(),
            scanned_sources: scanned_sources.into_boxed_slice(),
            alloc_sections: alloc_sections.into_boxed_slice(),
            relocation_sections: relocation_sections.into_boxed_slice(),
        }
    }

    /// Builds a section-granularity layout seed from a scanned module.
    pub fn from_scanned<D>(
        owner: LinkModuleId,
        module: &ScannedDylib<D>,
        arena: &mut LayoutSectionArena,
    ) -> Self
    where
        D: 'static,
    {
        let mut section_links = Vec::new();
        let mut mappings = Vec::new();
        for section in module.sections() {
            let section_id = arena.insert(owner, LayoutSectionMetadata::from_scanned(section));
            section_links.push((
                section_id,
                section.linked_section_id(),
                section.info_section_id(),
            ));
            mappings.push((section.id(), section_id));
        }

        let layout = Self::from_sections(mappings, arena);
        for (section_id, linked_scanned, info_scanned) in section_links {
            let linked_section = linked_scanned.and_then(|id| layout.section_id(id));
            let info_section = info_scanned.and_then(|id| layout.section_id(id));
            if let Some(metadata) = arena.get_mut(section_id) {
                metadata.set_links(linked_section, info_section);
            }
        }

        layout
    }

    /// Returns every section id owned by the module.
    #[inline]
    pub fn sections(&self) -> &[LayoutSectionId] {
        &self.sections
    }

    /// Returns whether this module owns `section`.
    #[inline]
    pub fn contains_section(&self, section: LayoutSectionId) -> bool {
        self.sections.contains(&section)
    }

    /// Returns the allocatable section ids that participate in default packing.
    #[inline]
    pub fn alloc_sections(&self) -> &[LayoutSectionId] {
        &self.alloc_sections
    }

    /// Returns the relocation section ids owned by the module.
    #[inline]
    pub fn relocation_sections(&self) -> &[LayoutSectionId] {
        &self.relocation_sections
    }

    /// Returns one section id by its original scanned section id.
    #[inline]
    pub fn section_id(&self, section: ScannedSectionId) -> Option<LayoutSectionId> {
        self.sections
            .iter()
            .zip(self.scanned_sources.iter())
            .find_map(|(section_id, source)| (*source == Some(section)).then_some(*section_id))
    }

    /// Iterates over every known section mapping for this module.
    #[inline]
    pub fn section_entries(&self) -> impl Iterator<Item = (&ScannedSectionId, &LayoutSectionId)> {
        self.sections
            .iter()
            .zip(self.scanned_sources.iter())
            .filter_map(|(section_id, source)| source.as_ref().map(|scanned| (scanned, section_id)))
    }
}
