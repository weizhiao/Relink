//! Pre-mapping dynamic-library descriptions and lazily readable section data.

use crate::{
    ParseDynamicError, ParseEhdrError, ParsePhdrError, Result,
    elf::{
        ElfDyn, ElfHeader, ElfPhdr, ElfProgramType, ElfSectionType, ElfShdr, ElfStringTable,
        parse_dynamic_entries,
    },
    input::ElfReader,
    loader::ScanBuilder,
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::{fmt, mem::size_of, num::NonZeroUsize, ops::Index};
use elf::abi::{DF_1_NOW, DF_BIND_NOW, DF_STATIC_TLS};

struct DynamicScanParts {
    dynamic: ScannedDynamicInfo,
    strtab: Box<[u8]>,
    needed_libs: Box<[usize]>,
    rpath: Option<usize>,
    runpath: Option<usize>,
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

/// Read-only view over `DT_NEEDED` strings stored in a scanned dylib.
pub struct ScannedNeededLibs<'a> {
    strtab: &'a ElfStringTable,
    offsets: &'a [usize],
}

impl<'a> ScannedNeededLibs<'a> {
    #[inline]
    pub(crate) fn new(strtab: &'a ElfStringTable, offsets: &'a [usize]) -> Self {
        Self { strtab, offsets }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&'a str> {
        self.offsets
            .get(index)
            .map(|offset| self.strtab.get_str(*offset))
    }
}

impl<'a> Index<usize> for ScannedNeededLibs<'a> {
    type Output = str;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("DT_NEEDED index out of bounds")
    }
}

impl<D> fmt::Debug for ScannedDylib<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedDylib")
            .field("name", &self.name)
            .field("needed_libs", &self.needed_libs)
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

    /// Returns the DT_NEEDED entries.
    #[inline]
    pub fn needed_libs(&self) -> ScannedNeededLibs<'_> {
        ScannedNeededLibs::new(&self.strtab, &self.needed_libs)
    }

    /// Returns the scanned section table.
    #[inline]
    pub fn sections(&self) -> &[ElfShdr] {
        &self.sections
    }

    /// Returns the name of a scanned section using the stored `.shstrtab`.
    #[inline]
    pub fn section_name(&self, section: &ElfShdr) -> &str {
        self.shstrtab.get_str(section.sh_name() as usize)
    }

    /// Returns a section by name.
    #[inline]
    pub fn section(&self, name: &str) -> Option<&ElfShdr> {
        self.sections
            .iter()
            .find(|section| self.section_name(section) == name)
    }

    /// Reads the bytes for a file-backed section with the given name on demand.
    ///
    /// To distinguish between a missing section and a non-file-backed one such as
    /// `.bss`, use [`Self::section`] and inspect [`ElfShdr::section_type`].
    #[inline]
    pub fn section_content(&mut self, name: &str) -> Result<Option<Box<[u8]>>> {
        let Some((offset, size, is_file_backed)) = self.section(name).map(|section| {
            (
                section.sh_offset(),
                section.sh_size(),
                section.section_type() != ElfSectionType::NOBITS,
            )
        }) else {
            return Ok(None);
        };
        if !is_file_backed {
            return Ok(None);
        }

        self.read_bytes(offset, size).map(Some)
    }

    /// Reads raw bytes from the underlying ELF reader at the given file offset.
    #[inline]
    pub fn read_bytes(&mut self, offset: usize, len: usize) -> Result<Box<[u8]>> {
        read_bytes_vec(&mut *self.reader, offset, len).map(Vec::into_boxed_slice)
    }

    /// Returns the underlying reader used to access the scanned ELF image.
    #[inline]
    pub fn reader(&mut self) -> &mut dyn ElfReader {
        &mut *self.reader
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

    let shdrs = read_typed::<ElfShdr>(object, start, ehdr.e_shnum())?;
    let shstrndx = ehdr.e_shstrndx();
    let shstrtab = match shdrs.get(shstrndx) {
        Some(shdr) if shdr.section_type() != ElfSectionType::NOBITS => {
            read_bytes_vec(object, shdr.sh_offset(), shdr.sh_size())?
        }
        _ => return Err(ParseEhdrError::MissingSectionHeaders.into()),
    };

    let sections = shdrs
        .into_iter()
        .filter(|shdr| shdr.section_type() != ElfSectionType::NULL)
        .collect::<Vec<_>>()
        .into_boxed_slice();

    Ok((sections, shstrtab.into_boxed_slice()))
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

fn read_interp(object: &mut dyn ElfReader, phdrs: &[ElfPhdr]) -> Result<Option<Box<[u8]>>> {
    let Some(interp) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::INTERP)
    else {
        return Ok(None);
    };

    let bytes = read_bytes_vec(object, interp.p_offset(), interp.p_filesz())?;
    Ok(Some(bytes.into_boxed_slice()))
}

fn vaddr_to_file_offset(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<usize> {
    let (seg_offset, seg_start, _) = load_segment_bounds(vaddr, phdrs)?;
    seg_offset
        .checked_add(vaddr - seg_start)
        .ok_or(ParseDynamicError::AddressOverflow.into())
}

fn strtab_limit(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<usize> {
    let (_, _, seg_end) = load_segment_bounds(vaddr, phdrs)?;
    Ok(seg_end - vaddr)
}

fn load_segment_bounds(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<(usize, usize, usize)> {
    for phdr in phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    {
        let seg_start = phdr.p_vaddr();
        let seg_end = seg_start
            .checked_add(phdr.p_filesz())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        if seg_start <= vaddr && vaddr < seg_end {
            return Ok((phdr.p_offset(), seg_start, seg_end));
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

    let dyns = read_typed::<ElfDyn>(
        object,
        dynamic_phdr.p_offset(),
        dynamic_phdr.p_filesz() / size_of::<ElfDyn>(),
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
    let strtab = read_bytes_vec(object, strtab_file_off, strtab_size)?;

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
