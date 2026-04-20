//! Pre-mapping dynamic-library descriptions and lazily readable section data.

use crate::{
    AlignedBytes, ParseDynamicError, ParsePhdrError, Result,
    elf::{
        ElfDyn, ElfHeader, ElfPhdr, ElfProgramType, ElfRelType, ElfSectionFlags, ElfSectionType,
        ElfShdr, ElfStringTable, parse_dynamic_entries,
    },
    entity::entity_ref,
    input::{ElfReader, ElfReaderExt},
    loader::ScanBuilder,
};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, mem::size_of, num::NonZeroUsize, ptr};
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

struct SectionTableScan {
    sections: Box<[ElfShdr]>,
    shstrtab: Box<[u8]>,
}

/// The planning capability exposed by one scanned module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModuleCapability {
    /// The module has no usable section-table view for planning.
    Opaque,
    /// The module exposes section metadata/data, but not enough retained
    /// relocation inputs to support section reordering repair.
    SectionData,
    /// The module exposes enough retained relocation inputs for section-level
    /// reordering and repair.
    SectionReorderable,
}

impl ModuleCapability {
    /// Returns whether this module exposes section metadata/data.
    #[inline]
    pub const fn has_section_data(self) -> bool {
        !matches!(self, Self::Opaque)
    }

    /// Returns whether this module supports section reordering repair.
    #[inline]
    pub const fn supports_reorder_repair(self) -> bool {
        matches!(self, Self::SectionReorderable)
    }
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
    _shstrtab_bytes: Option<Box<[u8]>>,
    rpath: Option<usize>,
    runpath: Option<usize>,
    needed_libs: Box<[usize]>,
    sections: Option<Box<[ElfShdr]>>,
    capability: ModuleCapability,
    reader: Box<dyn ElfReader + 'static>,
    dynamic: ScannedDynamicInfo,
    user_data: D,
}

/// A stable identifier for one scanned section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ScannedSectionId(usize);
entity_ref!(ScannedSectionId);

impl From<usize> for ScannedSectionId {
    #[inline]
    fn from(index: usize) -> Self {
        Self::new(index)
    }
}

impl From<ScannedSectionId> for usize {
    #[inline]
    fn from(id: ScannedSectionId) -> Self {
        id.index()
    }
}

/// A readable view over one scanned section and its metadata.
#[derive(Clone, Copy)]
pub struct ScannedSection<'a> {
    id: ScannedSectionId,
    name: &'a str,
    header: &'a ElfShdr,
}

/// Iterator over the usable section-table entries of a scanned module.
pub struct ScannedSections<'a> {
    sections: &'a [ElfShdr],
    shstrtab: *const u8,
    index: usize,
}

impl<'a> ScannedSections<'a> {
    #[inline]
    fn new(sections: &'a [ElfShdr], shstrtab: *const u8) -> Self {
        Self {
            sections,
            shstrtab,
            index: 0,
        }
    }

    #[inline]
    fn section_name(&self, section: &ElfShdr) -> &'a str {
        let table = ElfStringTable::new(self.shstrtab);
        table.get_str(section.sh_name() as usize)
    }
}

impl<'a> Iterator for ScannedSections<'a> {
    type Item = ScannedSection<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.sections.get(self.index)?;
        let id = ScannedSectionId::new(self.index);
        self.index += 1;
        Some(ScannedSection::new(id, self.section_name(header), header))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.sections.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ScannedSections<'_> {}

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
            .field(
                "sections",
                &self.sections.as_ref().map_or(0, |sections| sections.len()),
            )
            .field("capability", &self.capability)
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
        let section_scan = scan_sections(reader.as_mut(), &ehdr)?;
        let strtab_view = ElfStringTable::new(strtab.as_ptr());
        let capability = section_scan
            .as_ref()
            .map_or(ModuleCapability::Opaque, |scan| {
                classify_module_capability(&scan.sections)
            });

        Ok(Self {
            name,
            ehdr,
            phdrs,
            interp,
            _strtab_bytes: strtab,
            strtab: strtab_view,
            _shstrtab_bytes: section_scan.as_ref().map(|scan| scan.shstrtab.clone()),
            rpath,
            runpath,
            needed_libs,
            sections: section_scan.map(|scan| scan.sections),
            capability,
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

    /// Returns the planning capability of this module.
    #[inline]
    pub const fn capability(&self) -> ModuleCapability {
        self.capability
    }

    #[inline]
    fn shstrtab(&self) -> Option<ElfStringTable> {
        self._shstrtab_bytes
            .as_ref()
            .map(|bytes| ElfStringTable::new(bytes.as_ptr()))
    }

    /// Returns whether the module exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        self.sections.is_some()
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr]> {
        self.sections.as_deref()
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: impl Into<ScannedSectionId>) -> Option<ScannedSection<'_>> {
        let id = id.into();
        let sections = self.sections.as_deref()?;
        let shstrtab = self.shstrtab()?;
        let header = sections.get(id.index())?;
        Some(ScannedSection::new(
            id,
            shstrtab.get_str(header.sh_name() as usize),
            header,
        ))
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> ScannedSections<'_> {
        ScannedSections::new(
            self.sections.as_deref().unwrap_or(&[]),
            self._shstrtab_bytes
                .as_deref()
                .map_or(ptr::null(), <[u8]>::as_ptr),
        )
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

    /// Captures one section's backing bytes.
    pub fn section_data(
        &mut self,
        id: impl Into<ScannedSectionId>,
    ) -> Result<Option<AlignedBytes>> {
        let Some(section) = self.section(id) else {
            return Ok(None);
        };

        if section.is_nobits() {
            return Ok(Some(
                AlignedBytes::with_len(section.size()).expect("failed to allocate section bytes"),
            ));
        }

        Ok(Some(
            self.read_bytes(section.file_offset(), section.size())?,
        ))
    }

    #[inline]
    fn read_bytes(&mut self, offset: usize, len: usize) -> Result<AlignedBytes> {
        let mut bytes = AlignedBytes::with_len(len).ok_or(ParseDynamicError::AddressOverflow)?;
        self.reader.read_slice(bytes.as_mut(), offset)?;
        Ok(bytes)
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

    #[inline]
    pub(crate) fn into_reader(self) -> Box<dyn ElfReader + 'static> {
        self.reader
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

fn scan_sections(object: &mut dyn ElfReader, ehdr: &ElfHeader) -> Result<Option<SectionTableScan>> {
    if ehdr.e_shnum() == 0 {
        return Ok(None);
    }

    let Some((start, _)) = ehdr.checked_shdr_layout()? else {
        return Ok(None);
    };

    let shdrs = object.read_to_vec::<ElfShdr>(start, ehdr.e_shnum())?;
    let shstrndx = ehdr.e_shstrndx();
    let shstrtab = match shdrs.get(shstrndx) {
        Some(shdr) if shdr.section_type() != ElfSectionType::NOBITS => {
            object.read_to_vec(shdr.sh_offset(), shdr.sh_size())?
        }
        _ => return Ok(None),
    };

    Ok(Some(SectionTableScan {
        sections: shdrs.into_boxed_slice(),
        shstrtab: shstrtab.into_boxed_slice(),
    }))
}

fn classify_module_capability(sections: &[ElfShdr]) -> ModuleCapability {
    let mut saw_relocation_section = false;
    let mut saw_repairable_retained_relocations = false;

    for section in sections {
        if !matches!(
            section.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        ) {
            continue;
        }

        saw_relocation_section = true;
        if retained_relocations_are_repairable(sections, section) {
            saw_repairable_retained_relocations = true;
        }
    }

    if saw_repairable_retained_relocations {
        ModuleCapability::SectionReorderable
    } else if saw_relocation_section {
        ModuleCapability::SectionData
    } else {
        ModuleCapability::SectionData
    }
}

fn retained_relocations_are_repairable(sections: &[ElfShdr], section: &ElfShdr) -> bool {
    if section.flags().contains(ElfSectionFlags::ALLOC) {
        return false;
    }
    let target = section.sh_info() as usize;
    let symbol_table = section.sh_link() as usize;
    if target == 0 || symbol_table == 0 {
        return false;
    }
    if target >= sections.len() || symbol_table >= sections.len() {
        return false;
    }
    section.sh_entsize() == size_of::<ElfRelType>()
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
