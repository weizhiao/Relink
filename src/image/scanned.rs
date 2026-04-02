//! Pre-mapping dynamic-library descriptions and lazily readable section data.

use crate::{
    ParseDynamicError, ParseEhdrError, ParsePhdrError, Result,
    elf::{
        ElfDyn, ElfHeader, ElfPhdr, ElfProgramType, ElfRel, ElfRela, ElfSectionFlags,
        ElfSectionType, ElfShdr, ElfStringTable, parse_dynamic_entries,
    },
    input::{ElfReader, ElfReaderExt},
    loader::ScanBuilder,
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::{fmt, mem::size_of, num::NonZeroUsize};
use elf::abi::{DF_1_NOW, DF_BIND_NOW, DF_STATIC_TLS};

struct DynamicScanParts {
    dynamic: ScannedDynamicInfo,
    strtab: Box<[u8]>,
    needed_libs: Box<[usize]>,
    rpath: Option<usize>,
    runpath: Option<usize>,
}

struct SegmentBounds {
    offset: usize,
    start: usize,
    end: usize,
}

/// Dynamic-library metadata collected before the object is mapped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScannedDynamicInfo {
    bind_now: bool,
    static_tls: bool,
}

impl ScannedDynamicInfo {
    #[inline]
    pub(crate) const fn new(bind_now: bool, static_tls: bool) -> Self {
        Self {
            bind_now,
            static_tls,
        }
    }

    /// Returns whether the object requests eager binding.
    #[inline]
    pub fn bind_now(&self) -> bool {
        self.bind_now
    }

    /// Returns whether the object requests static TLS.
    #[inline]
    pub fn static_tls(&self) -> bool {
        self.static_tls
    }
}

/// A dynamic library that has been parsed but not yet mapped into memory.
pub struct ScannedDylib<D = ()>
where
    D: 'static,
{
    name: String,
    ehdr: ElfHeader,
    phdrs: Box<[ElfPhdr]>,
    interp: Option<Box<[u8]>>,
    _strtab_bytes: Box<[u8]>,
    strtab: ElfStringTable,
    _shstrtab_bytes: Box<[u8]>,
    shstrtab: ElfStringTable,
    rpath: Option<usize>,
    runpath: Option<usize>,
    needed_libs: Box<[usize]>,
    sections: Box<[ElfShdr]>,
    reader: Box<dyn ElfReader + 'static>,
    dynamic: ScannedDynamicInfo,
    user_data: D,
}

/// The raw encoding used by one retained relocation section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannedRelocationFormat {
    /// ELF `SHT_REL` entries with implicit addends.
    Rel,
    /// ELF `SHT_RELA` entries with explicit addends.
    Rela,
}

/// The addend representation carried by a retained relocation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannedRelocationAddend {
    /// The addend is stored directly in the relocation entry.
    Explicit(isize),
    /// The addend must be read from the relocation target contents.
    Implicit,
}

/// A normalized retained relocation entry discovered from a section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScannedRelocation {
    offset: usize,
    relocation_type: usize,
    symbol_index: usize,
    addend: ScannedRelocationAddend,
}

impl ScannedRelocation {
    #[inline]
    pub(crate) fn new(
        offset: usize,
        relocation_type: usize,
        symbol_index: usize,
        addend: ScannedRelocationAddend,
    ) -> Self {
        Self {
            offset,
            relocation_type,
            symbol_index,
            addend,
        }
    }

    /// Returns the relocation offset within the target section.
    #[inline]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the architecture-specific relocation kind.
    #[inline]
    pub const fn relocation_type(&self) -> usize {
        self.relocation_type
    }

    /// Returns the symbol-table index referenced by the relocation.
    #[inline]
    pub const fn symbol_index(&self) -> usize {
        self.symbol_index
    }

    /// Returns the relocation addend representation.
    #[inline]
    pub const fn addend(&self) -> ScannedRelocationAddend {
        self.addend
    }
}

/// An owned snapshot of one retained relocation section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedRelocationSection {
    id: ScannedSectionId,
    name: Box<str>,
    format: ScannedRelocationFormat,
    file_offset: usize,
    size: usize,
    alignment: usize,
    target_section: Option<ScannedSectionId>,
    symbol_table_section: Option<ScannedSectionId>,
    entries: Box<[ScannedRelocation]>,
}

impl ScannedRelocationSection {
    #[inline]
    pub(crate) fn new(
        id: ScannedSectionId,
        name: Box<str>,
        format: ScannedRelocationFormat,
        file_offset: usize,
        size: usize,
        alignment: usize,
        target_section: Option<ScannedSectionId>,
        symbol_table_section: Option<ScannedSectionId>,
        entries: Box<[ScannedRelocation]>,
    ) -> Self {
        Self {
            id,
            name,
            format,
            file_offset,
            size,
            alignment: alignment.max(1),
            target_section,
            symbol_table_section,
            entries,
        }
    }

    /// Returns the stable section id of the relocation section.
    #[inline]
    pub const fn id(&self) -> ScannedSectionId {
        self.id
    }

    /// Returns the original section name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the relocation section uses `REL` or `RELA`.
    #[inline]
    pub const fn format(&self) -> ScannedRelocationFormat {
        self.format
    }

    /// Returns the original file offset from the input image.
    #[inline]
    pub const fn file_offset(&self) -> usize {
        self.file_offset
    }

    /// Returns the original section size in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the section alignment in bytes.
    #[inline]
    pub const fn alignment(&self) -> usize {
        self.alignment
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

/// The high-level memory role of one scanned allocatable section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannedMemoryKind {
    /// Executable code.
    Code,
    /// Read-only data.
    ReadOnlyData,
    /// Writable process-global data.
    WritableData,
    /// Thread-local data or zero-fill TLS storage.
    ThreadLocalData,
}

/// The owned backing captured for one scanned memory section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannedMemoryData {
    /// File-backed bytes captured from the input image.
    Bytes(Box<[u8]>),
    /// Zero-fill storage such as `.bss` or `.tbss`.
    ZeroFill { size: usize },
}

impl ScannedMemoryData {
    /// Returns the logical section size in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::ZeroFill { size } => *size,
        }
    }

    /// Returns whether the section contains no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An owned snapshot of one allocatable section and its initial contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedMemorySection {
    id: ScannedSectionId,
    name: Box<str>,
    kind: ScannedMemoryKind,
    address: usize,
    file_offset: usize,
    size: usize,
    alignment: usize,
    data: ScannedMemoryData,
}

impl ScannedMemorySection {
    #[inline]
    pub(crate) fn new(
        id: ScannedSectionId,
        name: Box<str>,
        kind: ScannedMemoryKind,
        address: usize,
        file_offset: usize,
        size: usize,
        alignment: usize,
        data: ScannedMemoryData,
    ) -> Self {
        Self {
            id,
            name,
            kind,
            address,
            file_offset,
            size,
            alignment,
            data,
        }
    }

    /// Returns the stable section id.
    #[inline]
    pub const fn id(&self) -> ScannedSectionId {
        self.id
    }

    /// Returns the original section name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the high-level memory role of the section.
    #[inline]
    pub const fn kind(&self) -> ScannedMemoryKind {
        self.kind
    }

    /// Returns the original virtual address from the input image.
    #[inline]
    pub const fn address(&self) -> usize {
        self.address
    }

    /// Returns the original file offset from the input image.
    #[inline]
    pub const fn file_offset(&self) -> usize {
        self.file_offset
    }

    /// Returns the logical size of the section in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the required alignment in bytes.
    #[inline]
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Returns the captured backing data.
    #[inline]
    pub fn data(&self) -> &ScannedMemoryData {
        &self.data
    }

    pub(crate) fn into_data(self) -> ScannedMemoryData {
        self.data
    }
}

/// A stable identifier for one scanned section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScannedSectionId(usize);

impl ScannedSectionId {
    /// Creates a new section id from a zero-based section-table index.
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the zero-based section-table index.
    #[inline]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// A readable view over one scanned section and its metadata.
#[derive(Clone, Copy)]
pub struct ScannedSection<'a> {
    id: ScannedSectionId,
    name: &'a str,
    header: &'a ElfShdr,
}

impl<'a> ScannedSection<'a> {
    #[inline]
    fn new(id: ScannedSectionId, name: &'a str, header: &'a ElfShdr) -> Self {
        Self { id, name, header }
    }

    /// Returns the stable section id.
    #[inline]
    pub const fn id(&self) -> ScannedSectionId {
        self.id
    }

    /// Returns the section name.
    #[inline]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the underlying ELF section header.
    #[inline]
    pub fn header(&self) -> &'a ElfShdr {
        self.header
    }

    /// Returns the parsed section type.
    #[inline]
    pub fn section_type(&self) -> ElfSectionType {
        self.header.section_type()
    }

    /// Returns the parsed section flags.
    #[inline]
    pub fn flags(&self) -> ElfSectionFlags {
        self.header.flags()
    }

    /// Returns the section address.
    #[inline]
    pub fn address(&self) -> usize {
        self.header.sh_addr()
    }

    /// Returns the section file offset.
    #[inline]
    pub fn file_offset(&self) -> usize {
        self.header.sh_offset()
    }

    /// Returns the section size in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.header.sh_size()
    }

    /// Returns the section alignment in bytes.
    #[inline]
    pub fn alignment(&self) -> usize {
        self.header.sh_addralign()
    }

    /// Returns whether the section contributes to the loaded memory image.
    #[inline]
    pub fn is_allocated(&self) -> bool {
        self.flags().contains(ElfSectionFlags::ALLOC)
    }

    /// Returns whether the section is writable after mapping.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags().contains(ElfSectionFlags::WRITE)
    }

    /// Returns whether the section is executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.flags().contains(ElfSectionFlags::EXECINSTR)
    }

    /// Returns whether the section belongs to TLS storage.
    #[inline]
    pub fn is_tls(&self) -> bool {
        self.flags().contains(ElfSectionFlags::TLS)
    }

    /// Returns whether the section is zero-fill only (`SHT_NOBITS`).
    #[inline]
    pub fn is_nobits(&self) -> bool {
        self.section_type() == ElfSectionType::NOBITS
    }

    /// Returns whether the section stores retained relocations.
    #[inline]
    pub fn is_relocation_section(&self) -> bool {
        matches!(
            self.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        )
    }

    /// Returns the linked section id referenced by `sh_link`, when non-zero.
    #[inline]
    pub fn linked_section_id(&self) -> Option<ScannedSectionId> {
        (self.header.sh_link() != 0)
            .then_some(ScannedSectionId::new(self.header.sh_link() as usize))
    }

    /// Returns the info section id referenced by `sh_info`, when non-zero.
    #[inline]
    pub fn info_section_id(&self) -> Option<ScannedSectionId> {
        (self.header.sh_info() != 0)
            .then_some(ScannedSectionId::new(self.header.sh_info() as usize))
    }

    /// Returns the high-level memory role of the section when it is allocatable.
    #[inline]
    pub fn memory_kind(&self) -> Option<ScannedMemoryKind> {
        if !self.is_allocated() {
            return None;
        }

        Some(if self.is_tls() {
            ScannedMemoryKind::ThreadLocalData
        } else if self.is_executable() {
            ScannedMemoryKind::Code
        } else if self.is_writable() {
            ScannedMemoryKind::WritableData
        } else {
            ScannedMemoryKind::ReadOnlyData
        })
    }
}

impl<'a> fmt::Debug for ScannedSection<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedSection")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("type", &self.section_type())
            .field("size", &self.size())
            .field("align", &self.alignment())
            .finish()
    }
}

impl<D> fmt::Debug for ScannedDylib<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedDylib")
            .field("name", &self.name)
            .field("needed_libs", &self.needed_libs().collect::<Vec<_>>())
            .field("sections", &self.sections.len())
            .field("bind_now", &self.dynamic.bind_now)
            .field("static_tls", &self.dynamic.static_tls)
            .finish()
    }
}

impl<D> ScannedDylib<D> {
    pub(crate) fn from_builder(builder: ScanBuilder<D>) -> Result<Self> {
        let ScanBuilder {
            name,
            ehdr,
            phdrs,
            mut reader,
            user_data,
        } = builder;
        let interp = read_interp(reader.as_mut(), &phdrs)?;
        let DynamicScanParts {
            dynamic,
            strtab,
            needed_libs,
            rpath,
            runpath,
        } = scan_dynamic(reader.as_mut(), &phdrs)?;
        let (sections, shstrtab) = scan_sections(reader.as_mut(), &ehdr)?;
        let strtab_view = ElfStringTable::new(strtab.as_ptr());
        let shstrtab_view = ElfStringTable::new(shstrtab.as_ptr());

        Ok(Self {
            name,
            ehdr,
            phdrs,
            interp,
            _strtab_bytes: strtab,
            strtab: strtab_view,
            _shstrtab_bytes: shstrtab,
            shstrtab: shstrtab_view,
            rpath,
            runpath,
            needed_libs,
            sections,
            reader,
            dynamic,
            user_data,
        })
    }

    /// Returns the file name or path selected for this library.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the short library name.
    #[inline]
    pub fn short_name(&self) -> &str {
        let name = self.name();
        name.rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(name)
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader {
        &self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr] {
        &self.phdrs
    }

    /// Returns the PT_INTERP string when present.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.interp.as_deref().and_then(|bytes| interp_str(bytes))
    }

    /// Returns the DT_RPATH string when present.
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.rpath.map(|offset| self.strtab.get_str(offset))
    }

    /// Returns the DT_RUNPATH string when present.
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.runpath.map(|offset| self.strtab.get_str(offset))
    }

    /// Returns one `DT_NEEDED` entry by index.
    #[inline]
    pub fn needed_lib(&self, index: usize) -> Option<&str> {
        self.needed_libs
            .get(index)
            .map(|offset| self.strtab.get_str(*offset))
    }

    /// Iterates over the `DT_NEEDED` entries.
    #[inline]
    pub fn needed_libs(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.needed_libs
            .iter()
            .map(|offset| self.strtab.get_str(*offset))
    }

    /// Returns the raw ELF section headers.
    #[inline]
    pub fn section_headers(&self) -> &[ElfShdr] {
        &self.sections
    }

    #[inline]
    fn section_name(&self, section: &ElfShdr) -> &str {
        self.shstrtab.get_str(section.sh_name() as usize)
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: ScannedSectionId) -> Option<ScannedSection<'_>> {
        let header = self.sections.get(id.index())?;
        Some(ScannedSection::new(id, self.section_name(header), header))
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> impl ExactSizeIterator<Item = ScannedSection<'_>> + '_ {
        self.sections.iter().enumerate().map(|(index, header)| {
            ScannedSection::new(
                ScannedSectionId::new(index),
                self.section_name(header),
                header,
            )
        })
    }

    /// Iterates over sections that contribute to the loaded memory image.
    #[inline]
    pub fn alloc_sections(&self) -> impl Iterator<Item = ScannedSection<'_>> {
        self.sections().filter(|section| section.is_allocated())
    }

    /// Iterates over retained relocation sections emitted into the section table.
    #[inline]
    pub fn relocation_sections(&self) -> impl Iterator<Item = ScannedSection<'_>> {
        self.sections()
            .filter(|section| section.is_relocation_section())
    }

    /// Captures one allocatable section together with its initial contents.
    pub fn snapshot_memory_section(
        &mut self,
        id: ScannedSectionId,
    ) -> Result<Option<ScannedMemorySection>> {
        let Some((name, kind, address, file_offset, size, alignment, is_nobits)) =
            self.section(id).and_then(|section| {
                Some((
                    section.name().into(),
                    section.memory_kind()?,
                    section.address(),
                    section.file_offset(),
                    section.size(),
                    section.alignment(),
                    section.is_nobits(),
                ))
            })
        else {
            return Ok(None);
        };

        let data = if is_nobits {
            ScannedMemoryData::ZeroFill { size }
        } else {
            ScannedMemoryData::Bytes(self.read_bytes(file_offset, size)?)
        };

        Ok(Some(ScannedMemorySection::new(
            id,
            name,
            kind,
            address,
            file_offset,
            size,
            alignment,
            data,
        )))
    }

    /// Captures every allocatable section together with its initial contents.
    pub fn snapshot_memory_sections(&mut self) -> Result<Box<[ScannedMemorySection]>> {
        let ids = self
            .alloc_sections()
            .map(|section| section.id())
            .collect::<Vec<_>>();
        let mut sections = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(section) = self.snapshot_memory_section(id)? {
                sections.push(section);
            }
        }

        Ok(sections.into_boxed_slice())
    }

    /// Captures one retained relocation section and normalizes its entries.
    pub fn snapshot_relocation_section(
        &mut self,
        id: ScannedSectionId,
    ) -> Result<Option<ScannedRelocationSection>> {
        let Some((
            name,
            format,
            file_offset,
            size,
            alignment,
            target_section,
            symbol_table_section,
            entsize,
        )) = self.section(id).and_then(|section| {
            let format = match section.section_type() {
                ElfSectionType::REL => ScannedRelocationFormat::Rel,
                ElfSectionType::RELA => ScannedRelocationFormat::Rela,
                _ => return None,
            };
            Some((
                section.name().into(),
                format,
                section.file_offset(),
                section.size(),
                section.alignment(),
                section.info_section_id(),
                section.linked_section_id(),
                section.header().sh_entsize(),
            ))
        })
        else {
            return Ok(None);
        };

        let entries = match format {
            ScannedRelocationFormat::Rel => {
                snapshot_rel_entries(&mut *self.reader, file_offset, size, entsize)?
            }
            ScannedRelocationFormat::Rela => {
                snapshot_rela_entries(&mut *self.reader, file_offset, size, entsize)?
            }
        };

        Ok(Some(ScannedRelocationSection::new(
            id,
            name,
            format,
            file_offset,
            size,
            alignment,
            target_section,
            symbol_table_section,
            entries,
        )))
    }

    /// Captures every retained relocation section and normalizes its entries.
    pub fn snapshot_relocation_sections(&mut self) -> Result<Box<[ScannedRelocationSection]>> {
        let ids = self
            .relocation_sections()
            .map(|section| section.id())
            .collect::<Vec<_>>();
        let mut sections = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(section) = self.snapshot_relocation_section(id)? {
                sections.push(section);
            }
        }

        Ok(sections.into_boxed_slice())
    }

    #[inline]
    fn read_bytes(&mut self, offset: usize, len: usize) -> Result<Box<[u8]>> {
        read_bytes_vec(&mut *self.reader, offset, len).map(Vec::into_boxed_slice)
    }

    /// Returns the dynamic binding and TLS policy flags discovered during scan.
    #[inline]
    pub fn dynamic(&self) -> &ScannedDynamicInfo {
        &self.dynamic
    }

    /// Returns a reference to the user data associated with this scan result.
    #[inline]
    pub fn user_data(&self) -> &D {
        &self.user_data
    }

    /// Returns a mutable reference to the user data associated with this scan result.
    #[inline]
    pub fn user_data_mut(&mut self) -> &mut D {
        &mut self.user_data
    }
}

#[inline]
fn interp_str(bytes: &[u8]) -> Option<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

fn scan_sections(
    object: &mut dyn ElfReader,
    ehdr: &ElfHeader,
) -> Result<(Box<[ElfShdr]>, Box<[u8]>)> {
    if ehdr.e_shnum() == 0 {
        return Ok((Vec::new().into_boxed_slice(), Vec::new().into_boxed_slice()));
    }

    let Some((start, _)) = ehdr.checked_shdr_layout()? else {
        return Ok((Vec::new().into_boxed_slice(), Vec::new().into_boxed_slice()));
    };

    let shdrs = object.read_to_vec::<ElfShdr>(start, ehdr.e_shnum())?;
    let shstrndx = ehdr.e_shstrndx();
    let shstrtab = match shdrs.get(shstrndx) {
        Some(shdr) if shdr.section_type() != ElfSectionType::NOBITS => {
            object.read_to_vec(shdr.sh_offset(), shdr.sh_size())?
        }
        _ => return Err(ParseEhdrError::MissingSectionHeaders.into()),
    };

    Ok((shdrs.into_boxed_slice(), shstrtab.into_boxed_slice()))
}

fn read_bytes_vec(object: &mut dyn ElfReader, offset: usize, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    object.read(&mut bytes, offset)?;
    Ok(bytes)
}

fn read_typed<T>(object: &mut dyn ElfReader, offset: usize, count: usize) -> Result<Vec<T>> {
    let byte_len = count
        .checked_mul(size_of::<T>())
        .ok_or(ParseDynamicError::AddressOverflow)?;
    let mut values = Vec::<T>::with_capacity(count);
    unsafe {
        values.set_len(count);
    }
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(values.as_mut_ptr().cast::<u8>(), byte_len) };
    object.read(bytes, offset)?;
    Ok(values)
}

fn snapshot_rel_entries(
    object: &mut dyn ElfReader,
    offset: usize,
    size: usize,
    entsize: usize,
) -> Result<Box<[ScannedRelocation]>> {
    let count = relocation_entry_count(size, entsize, size_of::<ElfRel>())?;
    let rels = read_typed::<ElfRel>(object, offset, count)?;
    Ok(rels
        .into_iter()
        .map(|rel| {
            ScannedRelocation::new(
                rel.r_offset(),
                rel.r_type(),
                rel.r_symbol(),
                ScannedRelocationAddend::Implicit,
            )
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

fn snapshot_rela_entries(
    object: &mut dyn ElfReader,
    offset: usize,
    size: usize,
    entsize: usize,
) -> Result<Box<[ScannedRelocation]>> {
    let count = relocation_entry_count(size, entsize, size_of::<ElfRela>())?;
    let relas = read_typed::<ElfRela>(object, offset, count)?;
    Ok(relas
        .into_iter()
        .map(|rela| {
            ScannedRelocation::new(
                rela.r_offset(),
                rela.r_type(),
                rela.r_symbol(),
                ScannedRelocationAddend::Explicit(rela.r_addend(0)),
            )
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

fn relocation_entry_count(size: usize, entsize: usize, expected_entsize: usize) -> Result<usize> {
    if size == 0 {
        return Ok(0);
    }
    if entsize == 0 {
        return Err(ParseDynamicError::MalformedRelocationTable {
            detail: "relocation section entry size is zero",
        }
        .into());
    }
    if entsize != expected_entsize {
        return Err(ParseDynamicError::MalformedRelocationTable {
            detail: "relocation section entry size does not match the expected ELF relocation layout",
        }
        .into());
    }
    if !size.is_multiple_of(entsize) {
        return Err(ParseDynamicError::MalformedRelocationTable {
            detail: "relocation section size is not divisible by its entry size",
        }
        .into());
    }

    Ok(size / entsize)
}

#[cfg(test)]
mod tests {
    use super::relocation_entry_count;
    use crate::{Error, ParseDynamicError};

    #[test]
    fn relocation_entry_count_accepts_empty_sections() {
        assert_eq!(relocation_entry_count(0, 0, 24).unwrap(), 0);
    }

    #[test]
    fn relocation_entry_count_rejects_zero_entry_size_for_non_empty_sections() {
        let err = relocation_entry_count(24, 0, 24).unwrap_err();
        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::MalformedRelocationTable { .. })
        ));
    }

    #[test]
    fn relocation_entry_count_rejects_mismatched_entry_sizes() {
        let err = relocation_entry_count(48, 16, 24).unwrap_err();
        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::MalformedRelocationTable { .. })
        ));
    }
}

fn read_interp(object: &mut dyn ElfReader, phdrs: &[ElfPhdr]) -> Result<Option<Box<[u8]>>> {
    let Some(interp) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::INTERP)
    else {
        return Ok(None);
    };

    let bytes = object.read_to_vec(interp.p_offset(), interp.p_filesz())?;
    Ok(Some(bytes.into_boxed_slice()))
}

fn vaddr_to_file_offset(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<usize> {
    let bounds = load_segment_bounds(vaddr, phdrs)?;
    bounds
        .offset
        .checked_add(vaddr - bounds.start)
        .ok_or(ParseDynamicError::AddressOverflow.into())
}

fn strtab_limit(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<usize> {
    let bounds = load_segment_bounds(vaddr, phdrs)?;
    Ok(bounds.end - vaddr)
}

fn load_segment_bounds(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<SegmentBounds> {
    for phdr in phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    {
        let seg_start = phdr.p_vaddr();
        let seg_end = seg_start
            .checked_add(phdr.p_filesz())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        if seg_start <= vaddr && vaddr < seg_end {
            return Ok(SegmentBounds {
                offset: phdr.p_offset(),
                start: seg_start,
                end: seg_end,
            });
        }
    }

    Err(ParsePhdrError::MalformedProgramHeaders.into())
}

fn scan_dynamic(object: &mut dyn ElfReader, phdrs: &[ElfPhdr]) -> Result<DynamicScanParts> {
    let dynamic_phdr = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
        .ok_or(ParsePhdrError::MissingDynamicSection)?;
    if dynamic_phdr.p_filesz() % size_of::<ElfDyn>() != 0 {
        return Err(ParsePhdrError::MalformedProgramHeaders.into());
    }

    let dyns = object.read_to_vec::<ElfDyn>(
        dynamic_phdr.p_offset(),
        dynamic_phdr.p_filesz() / core::mem::size_of::<ElfDyn>(),
    )?;
    let parsed = parse_dynamic_entries(
        dyns.into_iter()
            .map(|dynamic| (dynamic.tag(), dynamic.value())),
    );

    let strtab_vaddr =
        NonZeroUsize::new(parsed.strtab_off).ok_or(ParseDynamicError::AddressOverflow)?;
    let strtab_file_off = vaddr_to_file_offset(strtab_vaddr.get(), phdrs)?;
    let strtab_size = match parsed.strtab_size {
        Some(size) => size.get(),
        None => strtab_limit(strtab_vaddr.get(), phdrs)?,
    };
    let strtab = object.read_to_vec(strtab_file_off, strtab_size)?;

    let needed_libs = parsed
        .needed_libs
        .into_iter()
        .map(|offset| offset.get())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let rpath = parsed.rpath_off.map(|offset| offset.get());
    let runpath = parsed.runpath_off.map(|offset| offset.get());

    Ok(DynamicScanParts {
        dynamic: ScannedDynamicInfo::new(
            parsed.flags & DF_BIND_NOW as usize != 0 || parsed.flags_1 & DF_1_NOW as usize != 0,
            parsed.flags & DF_STATIC_TLS as usize != 0,
        ),
        strtab: strtab.into_boxed_slice(),
        needed_libs,
        rpath,
        runpath,
    })
}
