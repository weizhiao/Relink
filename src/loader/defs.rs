use crate::{
    AlignedBytes, ParseEhdrError, Result,
    elf::{Elf32Layout, Elf64Layout, ElfFileType, ElfHeader, ElfLayout, ElfPhdr, ElfShdr},
    input::{ElfReader, ElfReaderExt},
    relocation::RelocationArch,
};
use core::mem::align_of;

pub(crate) struct ElfBuf {
    buf: AlignedBytes,
}

/// Reads and validates an ELF header for `Arch`.
pub(crate) fn read_ehdr<Arch: RelocationArch>(
    object: &(impl ElfReader + ?Sized),
) -> Result<ElfHeader<Arch::Layout>> {
    let raw = crate::aligned_bytes::read_value(|bytes| object.read(bytes, 0))?;
    let ehdr = ElfHeader::from_raw(raw, Arch::TARGET)?;
    Arch::validate_e_flags(ehdr.e_flags())?;
    Ok(ehdr)
}

impl ElfBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: AlignedBytes::default(),
        }
    }

    pub(crate) fn prepare_phdrs<'a, L: ElfLayout>(
        &'a mut self,
        ehdr: &ElfHeader<L>,
        object: &'a impl ElfReader,
    ) -> Result<Option<&'a [ElfPhdr<L>]>> {
        let Some((start, size)) = ehdr.checked_phdr_layout(object.len())? else {
            return Ok(None);
        };

        object
            .read_slice::<ElfPhdr<L>>(start, size, &mut self.buf)
            .map(Some)
    }

    pub(crate) fn prepare_shdrs<'a, L: ElfLayout>(
        &'a mut self,
        ehdr: &ElfHeader<L>,
        object: &'a impl ElfReader,
    ) -> Result<Option<&'a [ElfShdr<L>]>> {
        let Some((start, size)) = ehdr.checked_shdr_layout(object.len())? else {
            return Ok(None);
        };

        object
            .read_slice::<ElfShdr<L>>(start, size, &mut self.buf)
            .map(Some)
    }
}

const fn word_align_supports<T>() -> bool {
    align_of::<u64>() >= align_of::<T>()
}

const _: [(); 1] = [(); word_align_supports::<<Elf32Layout as ElfLayout>::Ehdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfPhdr<Elf32Layout>>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfShdr<Elf32Layout>>() as usize];
const _: [(); 1] = [(); word_align_supports::<<Elf64Layout as ElfLayout>::Ehdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfPhdr<Elf64Layout>>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfShdr<Elf64Layout>>() as usize];

#[derive(Clone, Copy)]
pub(crate) enum ExpectedElf {
    Dylib,
    Dynamic,
    Executable,
    #[cfg(feature = "object")]
    Relocatable,
}

impl ExpectedElf {
    #[inline]
    pub(crate) fn matches<L: ElfLayout>(self, ehdr: &ElfHeader<L>) -> bool {
        match self {
            Self::Dylib => ehdr.is_dylib(),
            Self::Dynamic | Self::Executable => ehdr.is_executable(),
            #[cfg(feature = "object")]
            Self::Relocatable => ehdr.file_type() == ElfFileType::REL,
        }
    }

    #[inline]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Dylib => "dylib",
            Self::Dynamic => "dynamic image",
            Self::Executable => "executable",
            #[cfg(feature = "object")]
            Self::Relocatable => "relocatable object",
        }
    }

    #[inline]
    pub(crate) const fn error(self, found: ElfFileType) -> ParseEhdrError {
        let expected: &'static [ElfFileType] = match self {
            Self::Dylib => &[ElfFileType::DYN],
            Self::Dynamic | Self::Executable => &[ElfFileType::EXEC, ElfFileType::DYN],
            #[cfg(feature = "object")]
            Self::Relocatable => &[ElfFileType::REL],
        };
        ParseEhdrError::UnexpectedFileType { expected, found }
    }
}
