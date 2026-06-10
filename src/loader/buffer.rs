use crate::{
    AlignedBytes, Result,
    elf::{Elf32Layout, Elf64Layout, ElfHeader, ElfLayout, ElfMachine, ElfPhdr, ElfShdr},
    input::{ElfReader, ElfReaderExt},
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
        object: &impl ElfReader,
        expected_machine: Option<ElfMachine>,
    ) -> Result<ElfHeader<L>> {
        let mut raw = MaybeUninit::<L::Ehdr>::uninit();
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(raw.as_mut_ptr().cast::<u8>(), L::EHDR_SIZE) };
        object.read(bytes, 0)?;
        ElfHeader::from_raw(unsafe { raw.assume_init() }, expected_machine)
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
