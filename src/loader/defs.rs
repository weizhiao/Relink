use crate::{
    AlignedBytes, ParseEhdrError, Result,
    elf::{Elf32Layout, Elf64Layout, ElfFileType, ElfHeader, ElfLayout, ElfPhdr, ElfShdr},
    input::{ElfReader, ElfReaderExt},
    relocation::RelocationArch,
};
use core::mem::{MaybeUninit, align_of, size_of};

pub(crate) struct ElfBuf {
    buf: AlignedBytes,
}

/// Reads and validates an ELF header for `Arch`.
pub(crate) fn read_ehdr<Arch: RelocationArch>(
    object: &impl ElfReader,
) -> Result<ElfHeader<Arch::Layout>> {
    let mut raw = MaybeUninit::<<Arch::Layout as ElfLayout>::Ehdr>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            raw.as_mut_ptr().cast::<u8>(),
            <Arch::Layout as ElfLayout>::EHDR_SIZE,
        )
    };
    object.read(bytes, 0)?;
    let ehdr = ElfHeader::from_raw(unsafe { raw.assume_init() }, Arch::TARGET)?;
    Arch::validate_e_flags(ehdr.e_flags())?;
    Ok(ehdr)
}

impl ElfBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: AlignedBytes::with_len(size_of::<elf::file::Elf64_Ehdr>())
                .expect("failed to initialize ElfBuf"),
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

        object.with_bytes::<ElfPhdr<L>, _, _>(start, size, &mut self.buf, |phdrs| Ok(Some(phdrs)))
    }

    pub(crate) fn prepare_shdrs<'a, L: ElfLayout>(
        &'a mut self,
        ehdr: &ElfHeader<L>,
        object: &'a impl ElfReader,
    ) -> Result<Option<&'a [ElfShdr<L>]>> {
        let Some((start, size)) = ehdr.checked_shdr_layout(object.len())? else {
            return Ok(None);
        };

        object.with_bytes::<ElfShdr<L>, _, _>(start, size, &mut self.buf, |shdrs| Ok(Some(shdrs)))
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
        match self {
            Self::Dylib => ParseEhdrError::ExpectedDylib { found },
            Self::Dynamic | Self::Executable => ParseEhdrError::ExpectedExecutable { found },
            #[cfg(feature = "object")]
            Self::Relocatable => ParseEhdrError::ExpectedRelocatable { found },
        }
    }
}
