use super::arena::{LayoutArenaId, LayoutMemoryClass};
use crate::{
    AlignedBytes,
    elf::{ElfSectionFlags, ElfSectionType},
    entity::{PrimaryMap, SecondaryMap, entity_ref},
    image::{ScannedDylib, ScannedSection, ScannedSectionId},
    linker::plan::LinkModuleId,
};
use alloc::{boxed::Box, vec::Vec};

/// A stable id for one section metadata record stored in [`super::MemoryLayoutPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutSectionId(usize);
entity_ref!(LayoutSectionId);

/// A derived address inside one placed section arena.
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

/// The immutable metadata tracked for one planned section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSectionMetadata {
    scanned_section: ScannedSectionId,
    name: Box<str>,
    section_type: ElfSectionType,
    section_flags: ElfSectionFlags,
    linked_section: Option<LayoutSectionId>,
    info_section: Option<LayoutSectionId>,
    source_address: usize,
    source_file_offset: usize,
    size: usize,
    alignment: usize,
}

impl LayoutSectionMetadata {
    /// Creates a new section metadata record.
    #[inline]
    pub fn new<T, U>(
        scanned_section: impl Into<ScannedSectionId>,
        name: impl Into<Box<str>>,
        section_type: ElfSectionType,
        section_flags: ElfSectionFlags,
        linked_section: Option<T>,
        info_section: Option<U>,
        source_address: usize,
        source_file_offset: usize,
        size: usize,
        alignment: usize,
    ) -> Self
    where
        T: Into<LayoutSectionId>,
        U: Into<LayoutSectionId>,
    {
        Self {
            scanned_section: scanned_section.into(),
            name: name.into(),
            section_type,
            section_flags,
            linked_section: linked_section.map(Into::into),
            info_section: info_section.map(Into::into),
            source_address,
            source_file_offset,
            size,
            alignment: alignment.max(1),
        }
    }

    pub(super) fn from_scanned(section: ScannedSection<'_>) -> Self {
        Self::new(
            section.id(),
            section.name(),
            section.section_type(),
            section.flags(),
            None::<LayoutSectionId>,
            None::<LayoutSectionId>,
            section.address(),
            section.file_offset(),
            section.size(),
            section.alignment(),
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

    /// Returns the original ELF section type.
    #[inline]
    pub const fn section_type(&self) -> ElfSectionType {
        self.section_type
    }

    /// Returns the original ELF section flags.
    #[inline]
    pub const fn section_flags(&self) -> ElfSectionFlags {
        self.section_flags
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
    pub fn is_allocated(&self) -> bool {
        self.section_flags.contains(ElfSectionFlags::ALLOC)
    }

    /// Returns whether this metadata record describes a retained relocation section.
    #[inline]
    pub const fn is_relocation(&self) -> bool {
        matches!(
            self.section_type,
            ElfSectionType::REL | ElfSectionType::RELA
        )
    }

    /// Returns whether this metadata record describes the dynamic section.
    #[inline]
    pub const fn is_dynamic(&self) -> bool {
        self.section_type.raw() == ElfSectionType::DYNAMIC.raw()
    }

    /// Returns the mapped memory class for loadable sections.
    #[inline]
    pub fn memory_class(&self) -> Option<LayoutMemoryClass> {
        if !self.is_allocated() {
            return None;
        }
        Some(if self.section_flags.contains(ElfSectionFlags::TLS) {
            LayoutMemoryClass::ThreadLocalData
        } else if self.section_flags.contains(ElfSectionFlags::EXECINSTR) {
            LayoutMemoryClass::Code
        } else if self.section_flags.contains(ElfSectionFlags::WRITE) {
            LayoutMemoryClass::WritableData
        } else {
            LayoutMemoryClass::ReadOnlyData
        })
    }

    /// Returns whether this metadata record describes a symbol-table section.
    #[inline]
    pub const fn is_symbol_table(&self) -> bool {
        matches!(
            self.section_type,
            ElfSectionType::SYMTAB | ElfSectionType::DYNSYM
        )
    }

    /// Returns whether this metadata record describes an allocated retained relocation section.
    #[inline]
    pub fn is_allocated_relocation(&self) -> bool {
        self.section_flags.contains(ElfSectionFlags::ALLOC) && self.is_relocation()
    }

    /// Returns the source ELF virtual address.
    #[inline]
    pub const fn source_address(&self) -> usize {
        self.source_address
    }

    /// Returns the source ELF file offset.
    #[inline]
    pub const fn source_file_offset(&self) -> usize {
        self.source_file_offset
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
        matches!(self.section_type, ElfSectionType::NOBITS)
    }
}

/// One complete section record tracked by the layout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSectionRecord {
    owner: LinkModuleId,
    metadata: LayoutSectionMetadata,
    data: Option<AlignedBytes>,
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
    pub fn data(&self) -> Option<&AlignedBytes> {
        self.data.as_ref()
    }

    /// Returns the materialized data of this section mutably, when present.
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut AlignedBytes> {
        self.data.as_mut()
    }

    #[inline]
    fn install_data(&mut self, data: AlignedBytes) {
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
    pub fn data(&self, id: LayoutSectionId) -> Option<&AlignedBytes> {
        self.record(id).and_then(LayoutSectionRecord::data)
    }

    /// Returns one materialized section-data record by id mutably.
    #[inline]
    pub fn data_mut(&mut self, id: LayoutSectionId) -> Option<&mut AlignedBytes> {
        self.record_mut(id).and_then(LayoutSectionRecord::data_mut)
    }

    pub(crate) fn with_disjoint_data_mut<R>(
        &mut self,
        read_a: LayoutSectionId,
        read_b: LayoutSectionId,
        write: LayoutSectionId,
        f: impl FnOnce(&AlignedBytes, &AlignedBytes, &mut AlignedBytes) -> R,
    ) -> Option<R> {
        debug_assert!(
            read_a != read_b && read_a != write && read_b != write,
            "disjoint section data request referenced the same section more than once",
        );

        let (before_write, write_record, after_write) = self.sections.split_at_mut(write)?;
        let write_index = before_write.len();
        let write_data = write_record.data_mut()?;

        let read_record = |section: LayoutSectionId| {
            let index = section.index();
            if index < write_index {
                before_write.get(index)
            } else {
                after_write.get(index - write_index - 1)
            }
        };

        let read_a_data = read_record(read_a)?.data()?;
        let read_b_data = read_record(read_b)?.data()?;
        Some(f(read_a_data, read_b_data, write_data))
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
        self.install_data(section, bytes)
    }

    #[inline]
    pub(crate) fn install_data(
        &mut self,
        section: LayoutSectionId,
        data: AlignedBytes,
    ) -> Option<LayoutSectionId> {
        let record = self.record_mut(section)?;
        record.install_data(data);
        Some(section)
    }

    pub(crate) fn install_scanned_data(
        &mut self,
        section: LayoutSectionId,
        bytes: impl Into<AlignedBytes>,
    ) {
        self.push_scanned(section, bytes.into())
            .expect("layout section arena failed to install scanned section data");
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
    scanned_sections: SecondaryMap<ScannedSectionId, LayoutSectionId>,
    alloc_sections: Box<[LayoutSectionId]>,
    relocation_sections: Box<[LayoutSectionId]>,
    symbol_table_sections: Box<[LayoutSectionId]>,
    allocated_relocation_sections: Box<[LayoutSectionId]>,
    dynamic_section: Option<LayoutSectionId>,
}

impl ModuleLayout {
    /// Creates an empty module layout.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates one module layout from explicit scanned-section mappings.
    pub fn from_sections<I, S>(sections: I, arena: &LayoutSectionArena) -> Self
    where
        I: IntoIterator<Item = (S, LayoutSectionId)>,
        S: Into<ScannedSectionId>,
    {
        let mut scanned_sections = SecondaryMap::default();
        let mut alloc_sections = Vec::new();
        let mut relocation_sections = Vec::new();
        let mut symbol_table_sections = Vec::new();
        let mut allocated_relocation_sections = Vec::new();
        let mut dynamic_section = None;

        for (scanned_section, section_id) in sections {
            let scanned_section = scanned_section.into();
            let previous = scanned_sections.insert(scanned_section, section_id);
            assert!(
                previous.is_none(),
                "module layout referenced duplicate scanned section id"
            );

            let section = arena
                .get(section_id)
                .expect("module layout referenced missing section metadata");
            if section.is_allocated() {
                alloc_sections.push(section_id);
            }
            if section.is_symbol_table() {
                symbol_table_sections.push(section_id);
            }
            if section.is_allocated_relocation() {
                allocated_relocation_sections.push(section_id);
            } else if section.is_relocation() {
                relocation_sections.push(section_id);
            }
            if section.is_dynamic() {
                let previous = dynamic_section.replace(section_id);
                assert!(
                    previous.is_none(),
                    "module layout referenced duplicate dynamic section"
                );
            }
        }

        Self {
            scanned_sections,
            alloc_sections: alloc_sections.into_boxed_slice(),
            relocation_sections: relocation_sections.into_boxed_slice(),
            symbol_table_sections: symbol_table_sections.into_boxed_slice(),
            allocated_relocation_sections: allocated_relocation_sections.into_boxed_slice(),
            dynamic_section,
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

    /// Returns whether this module owns `section`.
    #[inline]
    pub fn contains_section(&self, section: LayoutSectionId) -> bool {
        self.scanned_sections
            .iter()
            .any(|(_, section_id)| *section_id == section)
    }

    /// Returns the allocatable section ids that participate in default packing.
    #[inline]
    pub fn alloc_sections(&self) -> &[LayoutSectionId] {
        &self.alloc_sections
    }

    /// Returns the non-allocated relocation section ids owned by the module.
    #[inline]
    pub fn relocation_sections(&self) -> &[LayoutSectionId] {
        &self.relocation_sections
    }

    /// Returns the symbol-table section ids owned by the module.
    #[inline]
    pub fn symbol_table_sections(&self) -> &[LayoutSectionId] {
        &self.symbol_table_sections
    }

    /// Returns allocated retained relocation section ids owned by the module.
    #[inline]
    pub fn allocated_relocation_sections(&self) -> &[LayoutSectionId] {
        &self.allocated_relocation_sections
    }

    /// Returns the dynamic section owned by the module, when present.
    #[inline]
    pub fn dynamic_section(&self) -> Option<LayoutSectionId> {
        self.dynamic_section
    }

    /// Returns one section id by its original scanned section id.
    #[inline]
    pub fn section_id(&self, section: impl Into<ScannedSectionId>) -> Option<LayoutSectionId> {
        self.scanned_sections.get(section.into()).copied()
    }

    /// Iterates over every known section mapping for this module.
    #[inline]
    pub fn section_entries(&self) -> impl Iterator<Item = (ScannedSectionId, &LayoutSectionId)> {
        self.scanned_sections
            .iter()
            .map(|(scanned, section)| (scanned, section))
    }
}
