use super::arena::{ArenaId, MemoryClass};
use crate::{
    AlignedBytes,
    elf::{ElfLayout, ElfSectionFlags, ElfSectionType},
    entity::{PrimaryMap, SecondaryMap, entity_ref},
    image::{ScannedDynamic, ScannedSection, ScannedSectionId},
    linker::plan::ModuleId,
};
use alloc::{boxed::Box, vec::Vec};

/// A stable id for one section metadata record stored in [`super::MemoryLayoutPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SectionId(usize);
entity_ref!(SectionId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Read,
    Write,
}

pub enum SectionDataAccessRef<'a> {
    Read(&'a [u8]),
    Write(&'a mut [u8]),
}

impl<'a> SectionDataAccessRef<'a> {
    #[inline]
    pub fn into_read(self) -> &'a [u8] {
        match self {
            Self::Read(data) => data,
            Self::Write(_) => panic!("section data access should be read-only"),
        }
    }

    #[inline]
    pub fn into_write(self) -> &'a mut [u8] {
        match self {
            Self::Write(data) => data,
            Self::Read(_) => panic!("section data access should be writable"),
        }
    }
}

/// A derived address inside one placed section arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionAddress {
    arena: ArenaId,
    offset: usize,
}

impl SectionAddress {
    /// Creates a new address inside one arena.
    #[inline]
    pub const fn new(arena: ArenaId, offset: usize) -> Self {
        Self { arena, offset }
    }

    /// Returns the destination arena.
    #[inline]
    pub const fn arena(self) -> ArenaId {
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
    arena: ArenaId,
    offset: usize,
    size: usize,
}

impl SectionPlacement {
    /// Creates a new section placement inside a physical arena.
    #[inline]
    pub const fn new(arena: ArenaId, offset: usize, size: usize) -> Self {
        Self {
            arena,
            offset,
            size,
        }
    }

    /// Returns the arena that owns the placed section.
    #[inline]
    pub const fn arena(self) -> ArenaId {
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
    pub const fn address(self) -> SectionAddress {
        SectionAddress::new(self.arena, self.offset)
    }
}

/// The immutable metadata tracked for one planned section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionMetadata {
    scanned_section: ScannedSectionId,
    name: Box<str>,
    section_type: ElfSectionType,
    section_flags: ElfSectionFlags,
    linked_section: Option<SectionId>,
    info_section: Option<SectionId>,
    source_address: usize,
    source_file_offset: usize,
    size: usize,
    alignment: usize,
}

impl SectionMetadata {
    pub(super) fn from_scanned<L: ElfLayout>(section: ScannedSection<'_, L>) -> Self {
        Self {
            scanned_section: section.id(),
            name: section.name().into(),
            section_type: section.section_type(),
            section_flags: section.flags(),
            linked_section: None,
            info_section: None,
            source_address: section.address(),
            source_file_offset: section.file_offset(),
            size: section.size(),
            alignment: section.alignment().max(1),
        }
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
    pub(in crate::linker) const fn linked_section(&self) -> Option<SectionId> {
        self.linked_section
    }

    /// Returns the normalized `sh_info` section reference, when present.
    #[inline]
    pub(in crate::linker) const fn info_section(&self) -> Option<SectionId> {
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
        linked_section: Option<SectionId>,
        info_section: Option<SectionId>,
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
    pub fn memory_class(&self) -> Option<MemoryClass> {
        if !self.is_allocated() {
            return None;
        }
        Some(if self.section_flags.contains(ElfSectionFlags::TLS) {
            MemoryClass::ThreadLocalData
        } else if self.section_flags.contains(ElfSectionFlags::EXECINSTR) {
            MemoryClass::Code
        } else if self.section_flags.contains(ElfSectionFlags::WRITE) {
            MemoryClass::WritableData
        } else {
            MemoryClass::ReadOnlyData
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

    #[inline]
    pub(in crate::linker) fn set_size(&mut self, size: usize) {
        self.size = size;
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
struct SectionRecord {
    owner: ModuleId,
    metadata: SectionMetadata,
    data: Option<AlignedBytes>,
    override_data: bool,
    placement: Option<SectionPlacement>,
}

impl SectionRecord {
    #[inline]
    fn new(owner: ModuleId, metadata: SectionMetadata) -> Self {
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
    const fn owner(&self) -> ModuleId {
        self.owner
    }

    /// Returns the immutable metadata of this section.
    #[inline]
    fn metadata(&self) -> &SectionMetadata {
        &self.metadata
    }

    /// Returns the immutable metadata of this section mutably.
    #[inline]
    fn metadata_mut(&mut self) -> &mut SectionMetadata {
        &mut self.metadata
    }

    /// Returns the materialized data of this section, when present.
    #[inline]
    fn data(&self) -> Option<&AlignedBytes> {
        self.data.as_ref()
    }

    /// Returns the materialized data of this section mutably, when present.
    #[inline]
    fn data_mut(&mut self) -> Option<&mut AlignedBytes> {
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
    const fn is_override(&self) -> bool {
        self.override_data
    }

    #[inline]
    fn mark_data_override(&mut self) {
        self.override_data = true;
    }

    /// Returns the concrete arena placement of this section, when present.
    #[inline]
    fn placement(&self) -> Option<SectionPlacement> {
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

    #[inline]
    fn resize_data(&mut self, byte_len: usize) -> Option<()> {
        self.data.as_mut()?.set_len(byte_len)?;
        self.metadata.set_size(byte_len);
        self.clear_placement();
        Some(())
    }
}

/// A dense arena of section records.
#[derive(Debug, Clone, Default)]
pub(crate) struct SectionArena {
    sections: PrimaryMap<SectionId, SectionRecord>,
}

impl SectionArena {
    #[inline]
    pub(in crate::linker) fn insert(
        &mut self,
        owner: ModuleId,
        metadata: SectionMetadata,
    ) -> SectionId {
        self.sections.push(SectionRecord::new(owner, metadata))
    }

    /// Returns one section metadata record by id.
    #[inline]
    pub(crate) fn get(&self, id: SectionId) -> Option<&SectionMetadata> {
        self.sections.get(id).map(SectionRecord::metadata)
    }

    /// Returns the owner module of one section.
    #[inline]
    pub(in crate::linker) fn owner(&self, id: SectionId) -> Option<ModuleId> {
        self.sections.get(id).map(SectionRecord::owner)
    }

    /// Returns one section metadata record by id mutably.
    #[inline]
    pub(crate) fn get_mut(&mut self, id: SectionId) -> Option<&mut SectionMetadata> {
        self.sections.get_mut(id).map(SectionRecord::metadata_mut)
    }

    /// Iterates over section ids and metadata records together.
    #[inline]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (SectionId, &SectionMetadata)> {
        self.sections
            .iter()
            .map(|(id, record)| (id, record.metadata()))
    }

    /// Returns one materialized section-data record by id.
    #[inline]
    pub(crate) fn data(&self, id: SectionId) -> Option<&AlignedBytes> {
        self.sections.get(id).and_then(SectionRecord::data)
    }

    /// Returns one materialized section-data record by id mutably.
    #[inline]
    pub(crate) fn data_mut(&mut self, id: SectionId) -> Option<&mut AlignedBytes> {
        self.sections.get_mut(id).and_then(SectionRecord::data_mut)
    }

    #[inline]
    pub(crate) fn resize_data(&mut self, id: SectionId, byte_len: usize) -> Option<()> {
        self.sections.get_mut(id)?.resize_data(byte_len)
    }

    pub(crate) fn with_disjoint_data<const N: usize, R>(
        &mut self,
        accesses: [(SectionId, DataAccess); N],
        f: impl FnOnce([SectionDataAccessRef<'_>; N]) -> R,
    ) -> Option<R> {
        for (index, (section, _)) in accesses.iter().enumerate() {
            if accesses[index + 1..]
                .iter()
                .any(|(other, _)| section == other)
            {
                return None;
            }
        }

        let mut records = [core::ptr::null_mut::<SectionRecord>(); N];
        for (record, (section, _)) in records.iter_mut().zip(accesses.iter().copied()) {
            *record = self.sections.get_mut(section)?;
        }

        for &record in &records {
            // SAFETY: `record` came from the arena above and is only used to
            // verify materialized data before creating the final borrowed view.
            if unsafe { (&*record).data().is_none() } {
                return None;
            }
        }

        // SAFETY: duplicate section ids were rejected above, so every raw
        // record pointer is distinct. Each section's data is borrowed exactly
        // once according to its requested access, and the references cannot
        // escape the callback.
        let data = core::array::from_fn(|index| {
            let record = records[index];
            match accesses[index].1 {
                DataAccess::Read => SectionDataAccessRef::Read(
                    unsafe { (&*record).data() }
                        .expect("section data access should be materialized")
                        .as_bytes(),
                ),
                DataAccess::Write => SectionDataAccessRef::Write(
                    unsafe { (&mut *record).data_mut() }
                        .expect("section data access should be materialized")
                        .as_bytes_mut(),
                ),
            }
        });

        Some(f(data))
    }

    #[inline]
    pub(crate) fn is_override(&self, section: SectionId) -> bool {
        self.sections
            .get(section)
            .is_some_and(SectionRecord::is_override)
    }

    #[inline]
    pub(crate) fn install_data(&mut self, section: SectionId, bytes: AlignedBytes) {
        let record = self
            .sections
            .get_mut(section)
            .expect("layout plan attempted to install scanned data for a missing section");
        record.install_data(bytes);
    }

    #[inline]
    pub(crate) fn mark_data_override(&mut self, section: SectionId) {
        if let Some(record) = self.sections.get_mut(section) {
            record.mark_data_override();
        }
    }

    /// Returns the concrete arena placement of one section, when present.
    #[inline]
    pub(crate) fn placement(&self, id: SectionId) -> Option<SectionPlacement> {
        self.sections.get(id).and_then(SectionRecord::placement)
    }

    /// Iterates over sections that currently have a physical arena placement.
    #[inline]
    pub(crate) fn placements(&self) -> impl Iterator<Item = (SectionId, SectionPlacement)> + '_ {
        self.sections.iter().filter_map(|(section, record)| {
            record.placement().map(|placement| (section, placement))
        })
    }

    /// Iterates over sections currently placed in `arena`.
    #[inline]
    pub(crate) fn placements_in(
        &self,
        arena: ArenaId,
    ) -> impl Iterator<Item = (SectionId, SectionPlacement)> + '_ {
        self.placements()
            .filter(move |(_, placement)| placement.arena() == arena)
    }

    #[inline]
    pub(crate) fn set_placement(
        &mut self,
        section: SectionId,
        placement: SectionPlacement,
    ) -> bool {
        let Some(record) = self.sections.get_mut(section) else {
            return false;
        };
        record.set_placement(placement);
        true
    }

    #[inline]
    pub(crate) fn clear_placement(&mut self, section: SectionId) -> Option<SectionPlacement> {
        self.sections
            .get_mut(section)
            .and_then(SectionRecord::clear_placement)
    }
}

/// One module's logical section view inside the layout plan.
#[derive(Debug, Clone, Default)]
pub struct ModuleLayout {
    scanned_sections: SecondaryMap<ScannedSectionId, SectionId>,
    alloc_sections: Box<[SectionId]>,
    relocation_sections: Box<[SectionId]>,
    symbol_table_sections: Box<[SectionId]>,
    allocated_relocation_sections: Box<[SectionId]>,
    dynamic_section: Option<SectionId>,
}

impl ModuleLayout {
    /// Creates an empty module layout.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates one module layout from explicit scanned-section mappings.
    pub(crate) fn from_sections<I, S>(sections: I, arena: &SectionArena) -> Self
    where
        I: IntoIterator<Item = (S, SectionId)>,
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
    pub(in crate::linker) fn from_scanned<L: ElfLayout>(
        owner: ModuleId,
        module: &ScannedDynamic<L>,
        arena: &mut SectionArena,
    ) -> Self {
        let mut section_links = Vec::new();
        let mut mappings = Vec::new();
        for section in module.sections() {
            let section_id = arena.insert(owner, SectionMetadata::from_scanned(section));
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

    /// Returns the allocatable section ids that participate in default packing.
    #[inline]
    pub(in crate::linker) fn alloc_sections(&self) -> &[SectionId] {
        &self.alloc_sections
    }

    /// Returns the non-allocated relocation section ids owned by the module.
    #[inline]
    pub(in crate::linker) fn relocation_sections(&self) -> &[SectionId] {
        &self.relocation_sections
    }

    /// Returns the symbol-table section ids owned by the module.
    #[inline]
    pub(in crate::linker) fn symbol_table_sections(&self) -> &[SectionId] {
        &self.symbol_table_sections
    }

    /// Returns allocated retained relocation section ids owned by the module.
    #[inline]
    pub(in crate::linker) fn allocated_relocation_sections(&self) -> &[SectionId] {
        &self.allocated_relocation_sections
    }

    /// Returns the dynamic section owned by the module, when present.
    #[inline]
    pub(in crate::linker) fn dynamic_section(&self) -> Option<SectionId> {
        self.dynamic_section
    }

    /// Returns one section id by its original scanned section id.
    #[inline]
    pub(in crate::linker) fn section_id(
        &self,
        section: impl Into<ScannedSectionId>,
    ) -> Option<SectionId> {
        self.scanned_sections.get(section.into()).copied()
    }
}
