use crate::{
    AlignedBytes, ParseEhdrError, ParsePhdrError, Result,
    elf::{Elf32Layout, Elf64Layout, ElfHeader, ElfLayout, ElfMachine, ElfPhdr, ElfShdr},
    input::ElfReader,
};
use core::mem::{MaybeUninit, align_of, size_of};

pub(crate) struct ElfBuf {
    pub(crate) buf: AlignedBytes,
}

impl ElfBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: AlignedBytes::with_len(size_of::<elf::file::Elf64_Ehdr>())
                .expect("failed to initialize ElfBuf"),
        }
    }

    /// Reads and parses the ELF header.
    ///
    /// When `expected_machine` is `Some(machine)` the parsed header is
    /// rejected unless its `e_machine` equals `machine`. `None` skips the
    /// machine check entirely (cross-architecture loading).
    pub(crate) fn prepare_ehdr<L: ElfLayout>(
        &mut self,
        object: &mut impl ElfReader,
        expected_machine: Option<ElfMachine>,
    ) -> Result<ElfHeader<L>> {
        let mut raw = MaybeUninit::<L::Ehdr>::uninit();
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(raw.as_mut_ptr().cast::<u8>(), L::EHDR_SIZE) };
        object.read(bytes, 0)?;
        ElfHeader::from_raw(unsafe { raw.assume_init() }, expected_machine)
    }

    pub(crate) fn prepare_phdrs<L: ElfLayout>(
        &mut self,
        ehdr: &ElfHeader<L>,
        object: &mut impl ElfReader,
    ) -> Result<Option<&[ElfPhdr<L>]>> {
        let Some((start, size)) = ehdr.checked_phdr_layout()? else {
            return Ok(None);
        };
        let count = ehdr.e_phnum();

        self.buf.set_len(size).ok_or(ParsePhdrError::malformed(
            "program header table is too large",
        ))?;
        object.read(self.buf.as_bytes_mut(), start)?;
        let phdrs = self
            .buf
            .try_cast_slice::<ElfPhdr<L>>()
            .ok_or(ParsePhdrError::malformed(
                "program header table is not aligned",
            ))?;
        if phdrs.len() != count {
            return Err(ParsePhdrError::malformed("program header count mismatch").into());
        }

        Ok(Some(phdrs))
    }

    #[cfg_attr(not(feature = "object"), allow(dead_code))]
    pub(crate) fn prepare_shdrs_mut<L: ElfLayout>(
        &mut self,
        ehdr: &ElfHeader<L>,
        object: &mut impl ElfReader,
    ) -> Result<Option<&mut [ElfShdr<L>]>> {
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
            .try_cast_slice_mut::<ElfShdr<L>>()
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

const _: [(); 1] = [(); word_align_supports::<<Elf32Layout as ElfLayout>::Ehdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfPhdr<Elf32Layout>>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfShdr<Elf32Layout>>() as usize];
const _: [(); 1] = [(); word_align_supports::<<Elf64Layout as ElfLayout>::Ehdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfPhdr<Elf64Layout>>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfShdr<Elf64Layout>>() as usize];
