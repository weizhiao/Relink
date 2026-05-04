use crate::{
    AlignedBytes, ParseEhdrError, ParsePhdrError, Result,
    elf::{EHDR_SIZE, ElfEhdr, ElfHeader, ElfPhdr, ElfShdr},
    input::ElfReader,
};
use core::mem::{MaybeUninit, align_of};

pub(crate) struct ElfBuf {
    pub(crate) buf: AlignedBytes,
}

impl ElfBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: AlignedBytes::with_len(EHDR_SIZE).expect("failed to initialize ElfBuf"),
        }
    }

    /// Reads and parses the ELF header.
    ///
    /// When `check_arch` is `false` the machine architecture check is skipped,
    /// enabling cross-architecture loading (e.g. loading x86-64 ELF on RISC-V).
    pub(crate) fn prepare_ehdr(
        &mut self,
        object: &mut impl ElfReader,
        check_arch: bool,
    ) -> Result<ElfHeader> {
        let mut raw = MaybeUninit::<ElfEhdr>::uninit();
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(raw.as_mut_ptr().cast::<u8>(), EHDR_SIZE) };
        object.read(bytes, 0)?;
        ElfHeader::from_raw(unsafe { raw.assume_init() }, check_arch)
    }

    pub(crate) fn prepare_phdrs(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<Option<&[ElfPhdr]>> {
        let Some((start, size)) = ehdr.checked_phdr_layout()? else {
            return Ok(None);
        };
        let count = ehdr.e_phnum();

        self.buf
            .set_len(size)
            .ok_or(ParsePhdrError::MalformedProgramHeaders)?;
        object.read(self.buf.as_bytes_mut(), start)?;
        let phdrs = self
            .buf
            .try_cast_slice::<ElfPhdr>()
            .ok_or(ParsePhdrError::MalformedProgramHeaders)?;
        if phdrs.len() != count {
            return Err(ParsePhdrError::MalformedProgramHeaders.into());
        }

        Ok(Some(phdrs))
    }

    #[cfg_attr(not(feature = "object"), allow(dead_code))]
    pub(crate) fn prepare_shdrs_mut(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<Option<&mut [ElfShdr]>> {
        let Some((start, size)) = ehdr.checked_shdr_layout()? else {
            return Ok(None);
        };
        let count = ehdr.e_shnum();

        self.buf
            .set_len(size)
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        object.read(self.buf.as_bytes_mut(), start)?;

        let shdrs = self
            .buf
            .try_cast_slice_mut::<ElfShdr>()
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        if shdrs.len() != count {
            return Err(ParseEhdrError::MissingSectionHeaders.into());
        }

        Ok(Some(shdrs))
    }
}

const fn word_align_supports<T>() -> bool {
    align_of::<u64>() >= align_of::<T>()
}

const _: [(); 1] = [(); word_align_supports::<ElfEhdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfPhdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfShdr>() as usize];
