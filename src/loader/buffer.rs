use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    elf::{EHDR_SIZE, ElfEhdr, ElfHeader, ElfPhdr, ElfShdr},
    input::{ElfReader, ElfReaderExt},
};
use alloc::vec::Vec;
use core::mem::{MaybeUninit, align_of, size_of};

pub(crate) struct AlignedBytes {
    words: Vec<u64>,
    valid_len: usize,
}

impl AlignedBytes {
    #[inline]
    fn required_words(byte_len: usize) -> Option<usize> {
        let word_size = size_of::<u64>();
        byte_len.checked_add(word_size - 1).map(|v| v / word_size)
    }

    pub(crate) fn with_len(byte_len: usize) -> Option<Self> {
        let words = Self::required_words(byte_len)?;
        let mut storage = Vec::new();
        storage.resize(words, 0);
        Some(Self {
            words: storage,
            valid_len: byte_len,
        })
    }

    pub(crate) fn set_len(&mut self, byte_len: usize) -> Option<()> {
        let words = Self::required_words(byte_len)?;
        if words > self.words.len() {
            self.words.resize(words, 0);
        }
        self.valid_len = byte_len;
        Some(())
    }

    #[inline]
    pub(crate) fn as_slice<T>(&self) -> &[T] {
        let elem_size = size_of::<T>();
        debug_assert!(self.valid_len % elem_size == 0);
        debug_assert!(align_of::<u64>() >= align_of::<T>());
        unsafe {
            core::slice::from_raw_parts(self.words.as_ptr().cast::<T>(), self.valid_len / elem_size)
        }
    }

    #[inline]
    pub(crate) fn as_slice_mut<T>(&mut self) -> &mut [T] {
        let elem_size = size_of::<T>();
        debug_assert!(self.valid_len % elem_size == 0);
        debug_assert!(align_of::<u64>() >= align_of::<T>());
        unsafe {
            core::slice::from_raw_parts_mut(
                self.words.as_mut_ptr().cast::<T>(),
                self.valid_len / elem_size,
            )
        }
    }
}

pub(crate) struct ElfBuf {
    pub(crate) buf: AlignedBytes,
}

impl ElfBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: AlignedBytes::with_len(EHDR_SIZE).expect("failed to initialize ElfBuf"),
        }
    }

    pub(crate) fn prepare_ehdr(&mut self, object: &mut impl ElfReader) -> Result<ElfHeader> {
        let mut raw = MaybeUninit::<ElfEhdr>::uninit();
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(raw.as_mut_ptr().cast::<u8>(), EHDR_SIZE) };
        object.read(bytes, 0)?;
        ElfHeader::from_raw(unsafe { raw.assume_init() })
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
        object.read_slice(self.buf.as_slice_mut::<ElfPhdr>(), start)?;
        let phdrs = self.buf.as_slice::<ElfPhdr>();
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
        object.read_slice(self.buf.as_slice_mut::<ElfShdr>(), start)?;

        let shdrs = self.buf.as_slice_mut::<ElfShdr>();
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
