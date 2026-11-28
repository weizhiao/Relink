//! ELF headers, sections, and dependency metadata available before mapping.

use crate::{
    ParseDynamicError, ParsePhdrError, ParseShdrError, Result,
    arch::NativeArch,
    elf::{
        ElfDyn, ElfDynamicTag, ElfHeader, ElfLayout, ElfPhdr, ElfProgramType, ElfSectionId,
        ElfSectionType, ElfShdr, NativeElfLayout, parse_dynamic_entries,
    },
    image::{ModuleSearch, SearchPathPool},
    input::{ElfReader, ElfReaderExt, ModulePath, ModuleSourceId, Path, PathBuf},
    loader::ScanBuilder,
    relocation::RelocationArch,
};
use alloc::{boxed::Box, vec::Vec};
use core::{ffi::CStr, fmt, mem::size_of, num::NonZeroUsize, ops::Range};

fn string_range(bytes: &[u8], offset: usize) -> Option<Range<usize>> {
    let string = CStr::from_bytes_until_nul(bytes.get(offset..)?).ok()?;
    Some(offset..offset + string.to_bytes().len())
}

struct DynamicScanParts {
    strtab: Box<[u8]>,
    needed_libs: Box<[Range<usize>]>,
    soname: Option<Range<usize>>,
    rpath: Option<Range<usize>>,
    runpath: Option<Range<usize>>,
}

impl DynamicScanParts {
    fn new<L: ElfLayout>(object: &dyn ElfReader, phdrs: &[ElfPhdr<L>]) -> Result<Self> {
        let dynamic_phdr = phdrs
            .iter()
            .find(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
            .ok_or(ParsePhdrError::MissingDynamicSection)?;
        let dynamic_entry_size = size_of::<ElfDyn<L>>();
        if dynamic_phdr.p_filesz() % dynamic_entry_size != 0 {
            return Err(ParseDynamicError::InvalidDynamicTableSize {
                size: dynamic_phdr.p_filesz(),
                entry_size: dynamic_entry_size,
            }
            .into());
        }

        let dyns = object.read_to_vec::<ElfDyn<L>>(
            dynamic_phdr.p_offset(),
            dynamic_phdr.p_filesz() / dynamic_entry_size,
        )?;
        let parsed = parse_dynamic_entries(
            dyns.into_iter()
                .map(|dynamic| (dynamic.tag(), dynamic.value())),
        );

        let strtab_vaddr =
            NonZeroUsize::new(parsed.strtab_off).ok_or(ParseDynamicError::AddressOverflow)?;
        let strtab_file_off = vaddr_to_file_offset(strtab_vaddr.get(), phdrs)?;
        let strtab_size = parsed
            .strtab_size
            .ok_or(ParseDynamicError::MissingRequiredTag {
                tag: ElfDynamicTag::STRSZ,
            })?
            .get();
        let strtab = object.read_to_vec(strtab_file_off, strtab_size)?;

        let string = |offset| {
            string_range(&strtab, offset).ok_or_else(|| {
                ParseDynamicError::malformed_table(
                    ElfDynamicTag::STRTAB,
                    "invalid string reference",
                )
            })
        };
        let needed_libs = parsed
            .needed_libs
            .into_iter()
            .map(|offset| string(offset.get()))
            .collect::<core::result::Result<_, _>>()?;
        let soname = parsed
            .soname_off
            .map(|offset| string(offset.get()))
            .transpose()?;
        let rpath = parsed.rpath_off.map(string).transpose()?;
        let runpath = parsed.runpath_off.map(string).transpose()?;

        Ok(Self {
            strtab: strtab.into_boxed_slice(),
            needed_libs,
            soname,
            rpath,
            runpath,
        })
    }
}

struct SectionTable<L: ElfLayout = NativeElfLayout> {
    sections: Box<[ElfShdr<L>]>,
    shstrtab: Box<[u8]>,
    names: Box<[Range<usize>]>,
}

impl<L: ElfLayout> SectionTable<L> {
    fn new(object: &dyn ElfReader, ehdr: &ElfHeader<L>) -> Result<Option<Self>> {
        if ehdr.e_shnum() == 0 {
            return Ok(None);
        }

        let Some((start, _)) = ehdr.checked_shdr_layout(object.len())? else {
            return Ok(None);
        };

        let shdrs = object.read_to_vec::<ElfShdr<L>>(start, ehdr.e_shnum())?;
        let mut name_table = ehdr.e_shstrndx();
        if name_table == usize::from(elf::abi::SHN_XINDEX) {
            name_table = shdrs[0].sh_link() as usize;
        }
        let shstrtab = match name_table {
            0 => Vec::new(),
            index => {
                let shdr = shdrs
                    .get(index)
                    .filter(|shdr| shdr.section_type() == ElfSectionType::STRTAB)
                    .ok_or_else(|| ParseShdrError::malformed("invalid section name table"))?;
                object.read_to_vec(shdr.sh_offset(), shdr.sh_size())?
            }
        };
        let names = shdrs
            .iter()
            .map(|header| match header.sh_name() {
                0 => Ok(0..0),
                offset => string_range(&shstrtab, offset as usize)
                    .ok_or_else(|| ParseShdrError::malformed("invalid section name")),
            })
            .collect::<core::result::Result<_, _>>()?;

        Ok(Some(Self {
            sections: shdrs.into_boxed_slice(),
            shstrtab: shstrtab.into_boxed_slice(),
            names,
        }))
    }

    fn iter(table: Option<&Self>) -> impl ExactSizeIterator<Item = ScannedSection<'_, L>> {
        let (headers, names, strings) = match table {
            Some(table) => (&*table.sections, &*table.names, &*table.shstrtab),
            None => (&[][..], &[][..], &[][..]),
        };
        headers
            .iter()
            .zip(names)
            .enumerate()
            .map(move |(index, (header, name))| ScannedSection {
                id: ElfSectionId::new(index),
                header,
                name: &strings[name.clone()],
            })
    }
}

/// A dynamic ELF image that has been parsed but not yet mapped into memory.
pub struct ScannedDynamic<Arch: RelocationArch = NativeArch> {
    source_id: ModuleSourceId,
    search: ModuleSearch,
    ehdr: ElfHeader<Arch::Layout>,
    phdrs: Box<[ElfPhdr<Arch::Layout>]>,
    interp: Option<Box<[u8]>>,
    strtab: Box<[u8]>,
    section_table: Option<SectionTable<Arch::Layout>>,
    needed_libs: Box<[Range<usize>]>,
    reader: Box<dyn ElfReader + 'static>,
}

/// A static executable that has been parsed but not yet mapped into memory.
pub struct ScannedExec<Arch: RelocationArch = NativeArch> {
    path: PathBuf,
    ehdr: ElfHeader<Arch::Layout>,
    phdrs: Box<[ElfPhdr<Arch::Layout>]>,
    interp: Option<Box<[u8]>>,
    section_table: Option<SectionTable<Arch::Layout>>,
}

/// A scanned ELF image classified by the metadata available before mapping.
#[derive(Debug)]
pub enum ScannedElf<Arch: RelocationArch = NativeArch> {
    /// An image with `PT_DYNAMIC` metadata.
    Dynamic(ScannedDynamic<Arch>),
    /// An executable without `PT_DYNAMIC` metadata.
    StaticExec(ScannedExec<Arch>),
}

pub(crate) struct ScannedDynamicLoadParts<Arch: RelocationArch = NativeArch> {
    pub(crate) ehdr: ElfHeader<Arch::Layout>,
    pub(crate) phdrs: Box<[ElfPhdr<Arch::Layout>]>,
    pub(crate) reader: Box<dyn ElfReader + 'static>,
}

/// A readable view over one scanned section and its metadata.
pub struct ScannedSection<'a, L: ElfLayout = NativeElfLayout> {
    id: ElfSectionId,
    name: &'a [u8],
    header: &'a ElfShdr<L>,
}

impl<L: ElfLayout> Copy for ScannedSection<'_, L> {}

impl<L: ElfLayout> Clone for ScannedSection<'_, L> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, L: ElfLayout> ScannedSection<'a, L> {
    /// Returns the stable section id.
    #[inline]
    pub const fn id(&self) -> ElfSectionId {
        self.id
    }

    /// Returns the section name.
    #[inline]
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// Returns the underlying ELF section header.
    #[inline]
    pub fn header(&self) -> &'a ElfShdr<L> {
        self.header
    }
}

impl<'a, L: ElfLayout> fmt::Debug for ScannedSection<'a, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedSection")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("type", &self.header.section_type())
            .field("size", &self.header.sh_size())
            .field("align", &self.header.sh_addralign())
            .finish()
    }
}

impl<Arch: RelocationArch> fmt::Debug for ScannedDynamic<Arch> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedDynamic")
            .field("path", &self.path())
            .field("soname", &self.soname())
            .field("needed_libs", &self.needed_libs().collect::<Vec<_>>())
            .field(
                "sections",
                &self
                    .section_table
                    .as_ref()
                    .map_or(0, |table| table.sections.len()),
            )
            .finish()
    }
}

impl<Arch: RelocationArch> fmt::Debug for ScannedExec<Arch> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedExec")
            .field("path", &self.path)
            .field(
                "sections",
                &self
                    .section_table
                    .as_ref()
                    .map_or(0, |table| table.sections.len()),
            )
            .finish()
    }
}

impl<Arch: RelocationArch> ScannedElf<Arch> {
    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        match self {
            Self::Dynamic(image) => image.path(),
            Self::StaticExec(image) => image.path(),
        }
    }

    /// Returns the ELF image identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &[u8] {
        match self {
            Self::Dynamic(image) => image.name(),
            Self::StaticExec(image) => image.name(),
        }
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader<Arch::Layout> {
        match self {
            Self::Dynamic(image) => image.ehdr(),
            Self::StaticExec(image) => image.ehdr(),
        }
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr<Arch::Layout>] {
        match self {
            Self::Dynamic(image) => image.phdrs(),
            Self::StaticExec(image) => image.phdrs(),
        }
    }

    /// Returns the bytes of the interpreter path, excluding the NUL terminator.
    #[inline]
    pub fn interp(&self) -> Option<&[u8]> {
        match self {
            Self::Dynamic(image) => image.interp(),
            Self::StaticExec(image) => image.interp(),
        }
    }

    /// Returns the dynamic scan data when this is a dynamic image.
    #[inline]
    pub fn as_dynamic(&self) -> Option<&ScannedDynamic<Arch>> {
        match self {
            Self::Dynamic(image) => Some(image),
            Self::StaticExec(_) => None,
        }
    }

    /// Returns the static executable scan data when this is a static executable.
    #[inline]
    pub fn as_static_exec(&self) -> Option<&ScannedExec<Arch>> {
        match self {
            Self::Dynamic(_) => None,
            Self::StaticExec(image) => Some(image),
        }
    }

    /// Consumes this value and returns dynamic scan data when present.
    #[inline]
    pub fn into_dynamic(self) -> Option<ScannedDynamic<Arch>> {
        match self {
            Self::Dynamic(image) => Some(image),
            Self::StaticExec(_) => None,
        }
    }

    /// Consumes this value and returns static executable scan data when present.
    #[inline]
    pub fn into_static_exec(self) -> Option<ScannedExec<Arch>> {
        match self {
            Self::Dynamic(_) => None,
            Self::StaticExec(image) => Some(image),
        }
    }

    /// Returns whether the image exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        match self {
            Self::Dynamic(image) => image.has_sections(),
            Self::StaticExec(image) => image.has_sections(),
        }
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr<Arch::Layout>]> {
        match self {
            Self::Dynamic(image) => image.section_headers(),
            Self::StaticExec(image) => image.section_headers(),
        }
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: ElfSectionId) -> Option<ScannedSection<'_, Arch::Layout>> {
        match self {
            Self::Dynamic(image) => image.section(id),
            Self::StaticExec(image) => image.section(id),
        }
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> impl ExactSizeIterator<Item = ScannedSection<'_, Arch::Layout>> {
        SectionTable::iter(match self {
            Self::Dynamic(image) => image.section_table.as_ref(),
            Self::StaticExec(image) => image.section_table.as_ref(),
        })
    }
}

impl<Arch: RelocationArch> ScannedDynamic<Arch> {
    pub(crate) fn from_builder(
        builder: ScanBuilder<Arch::Layout>,
        search_paths: Option<&mut SearchPathPool>,
    ) -> Result<Self> {
        let ScanBuilder {
            path,
            ehdr,
            phdrs,
            mut reader,
        } = builder;
        let source_id = reader.source_id();
        let interp = read_interp(reader.as_mut(), &phdrs)?;
        let DynamicScanParts {
            strtab,
            needed_libs,
            soname,
            rpath,
            runpath,
        } = DynamicScanParts::new(reader.as_mut(), &phdrs)?;
        let section_table = SectionTable::new(reader.as_mut(), &ehdr)?;
        let soname = soname.map(|range| &strtab[range]);
        let runpath = runpath.map(|range| &strtab[range]);
        let rpath = rpath.map(|range| &strtab[range]);
        let path = ModulePath::try_from(path).map_err(|_| crate::IoError::NullByteInPath)?;
        let search = match search_paths {
            Some(paths) => paths.module_search(path, soname, runpath, rpath),
            None => ModuleSearch::from_dynamic(path, soname, runpath, rpath),
        };
        Ok(Self {
            source_id,
            search,
            ehdr,
            phdrs,
            interp,
            strtab,
            section_table,
            needed_libs,
            reader,
        })
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.search.path()
    }

    /// Returns the ELF image identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &[u8] {
        self.search.name()
    }

    /// Returns the stable identity of this scanned source.
    #[inline]
    pub const fn source_id(&self) -> ModuleSourceId {
        self.source_id
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader<Arch::Layout> {
        &self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr<Arch::Layout>] {
        &self.phdrs
    }

    /// Returns the bytes of the interpreter path, excluding the NUL terminator.
    #[inline]
    pub fn interp(&self) -> Option<&[u8]> {
        self.interp.as_deref()
    }

    /// Returns expanded module search metadata.
    #[inline]
    pub fn search(&self) -> &ModuleSearch {
        &self.search
    }

    /// Returns the DT_SONAME string when present.
    #[inline]
    pub fn soname(&self) -> Option<&[u8]> {
        self.search.soname()
    }

    /// Returns one `DT_NEEDED` entry by index.
    #[inline]
    pub fn needed_lib(&self, index: usize) -> Option<&[u8]> {
        self.needed_libs
            .get(index)
            .map(|range| &self.strtab[range.clone()])
    }

    /// Iterates over the `DT_NEEDED` entries.
    #[inline]
    pub fn needed_libs(&self) -> impl ExactSizeIterator<Item = &[u8]> + '_ {
        self.needed_libs
            .iter()
            .map(|range| &self.strtab[range.clone()])
    }

    /// Returns whether the module exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        self.section_table.is_some()
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr<Arch::Layout>]> {
        self.section_table
            .as_ref()
            .map(|table| table.sections.as_ref())
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: ElfSectionId) -> Option<ScannedSection<'_, Arch::Layout>> {
        self.sections().nth(id.index())
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> impl ExactSizeIterator<Item = ScannedSection<'_, Arch::Layout>> {
        SectionTable::iter(self.section_table.as_ref())
    }

    pub(crate) fn into_load_parts(self) -> ScannedDynamicLoadParts<Arch> {
        let Self {
            ehdr,
            phdrs,
            reader,
            ..
        } = self;

        ScannedDynamicLoadParts {
            ehdr,
            phdrs,
            reader,
        }
    }
}

impl<Arch: RelocationArch> ScannedExec<Arch> {
    pub(crate) fn from_builder(builder: ScanBuilder<Arch::Layout>) -> Result<Self> {
        let ScanBuilder {
            path,
            ehdr,
            phdrs,
            mut reader,
        } = builder;
        let interp = read_interp(reader.as_mut(), &phdrs)?;
        let section_table = SectionTable::new(reader.as_mut(), &ehdr)?;

        Ok(Self {
            path,
            ehdr,
            phdrs,
            interp,
            section_table,
        })
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns the executable identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &[u8] {
        self.path().file_name()
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader<Arch::Layout> {
        &self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr<Arch::Layout>] {
        &self.phdrs
    }

    /// Returns the bytes of the interpreter path, excluding the NUL terminator.
    #[inline]
    pub fn interp(&self) -> Option<&[u8]> {
        self.interp.as_deref()
    }

    /// Returns whether the executable exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        self.section_table.is_some()
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr<Arch::Layout>]> {
        self.section_table
            .as_ref()
            .map(|table| table.sections.as_ref())
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: ElfSectionId) -> Option<ScannedSection<'_, Arch::Layout>> {
        self.sections().nth(id.index())
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> impl ExactSizeIterator<Item = ScannedSection<'_, Arch::Layout>> {
        SectionTable::iter(self.section_table.as_ref())
    }
}

fn read_interp<L: ElfLayout>(
    object: &dyn ElfReader,
    phdrs: &[ElfPhdr<L>],
) -> Result<Option<Box<[u8]>>> {
    let Some(interp) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::INTERP)
    else {
        return Ok(None);
    };

    let mut bytes = object.read_to_vec(interp.p_offset(), interp.p_filesz())?;
    let len = crate::elf::parse_interp(&bytes)?.len();
    bytes.truncate(len);
    Ok(Some(bytes.into_boxed_slice()))
}

fn vaddr_to_file_offset<L: ElfLayout>(vaddr: usize, phdrs: &[ElfPhdr<L>]) -> Result<usize> {
    for phdr in phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    {
        let seg_start = phdr.p_vaddr().get();
        let seg_end = seg_start
            .checked_add(phdr.p_filesz())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        if seg_start <= vaddr && vaddr < seg_end {
            return phdr
                .p_offset()
                .checked_add(vaddr - seg_start)
                .ok_or(ParseDynamicError::AddressOverflow.into());
        }
    }

    Err(ParsePhdrError::malformed("virtual address is not covered by a PT_LOAD segment").into())
}
