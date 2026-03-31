use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    elf::{EHDR_SIZE, ElfEhdr, ElfHeader, ElfPhdr, ElfShdr},
    input::ElfReader,
};
use alloc::vec::Vec;
use core::mem::{MaybeUninit, align_of, size_of};

pub(crate) struct AlignedBytes {
    words: Vec<usize>,
    valid_len: usize,
}

impl AlignedBytes {
    #[inline]
    fn required_words(byte_len: usize) -> Option<usize> {
        let word_size = size_of::<usize>();
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
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.valid_len) }
    }

    #[inline]
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.valid_len)
        }
    }

    #[inline]
    pub(crate) fn as_slice<T>(&self) -> Option<&[T]> {
        let elem_size = size_of::<T>();
        if elem_size == 0 || self.valid_len % elem_size != 0 {
            return None;
        }
        if align_of::<T>() > align_of::<usize>() {
            return None;
        }
        Some(unsafe {
            core::slice::from_raw_parts(self.words.as_ptr().cast::<T>(), self.valid_len / elem_size)
        })
    }

    #[inline]
    #[cfg_attr(not(feature = "object"), allow(dead_code))]
    pub(crate) fn as_slice_mut<T>(&mut self) -> Option<&mut [T]> {
        let elem_size = size_of::<T>();
        if elem_size == 0 || self.valid_len % elem_size != 0 {
            return None;
        }
        if align_of::<T>() > align_of::<usize>() {
            return None;
        }
        Some(unsafe {
            core::slice::from_raw_parts_mut(
                self.words.as_mut_ptr().cast::<T>(),
                self.valid_len / elem_size,
            )
        })
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
        object.read(self.buf.as_bytes_mut(), start)?;
        let phdrs = self
            .buf
            .as_slice::<ElfPhdr>()
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
            .as_slice_mut::<ElfShdr>()
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        if shdrs.len() != count {
            return Err(ParseEhdrError::MissingSectionHeaders.into());
        }

        Ok(Some(shdrs))
    }
}

const fn word_align_supports<T>() -> bool {
    align_of::<usize>() >= align_of::<T>()
}

const _: [(); 1] = [(); word_align_supports::<ElfEhdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfPhdr>() as usize];
const _: [(); 1] = [(); word_align_supports::<ElfShdr>() as usize];

#[cfg(test)]
mod tests {
    use super::AlignedBytes;

    #[test]
    fn aligned_bytes_grow_and_keep_byte_window() {
        let mut storage = AlignedBytes::with_len(4).expect("failed to initialize aligned bytes");
        storage.as_bytes_mut().copy_from_slice(&[1, 2, 3, 4]);

        storage.set_len(11).expect("failed to grow byte window");
        assert_eq!(storage.as_bytes().len(), 11);
        assert_eq!(&storage.as_bytes()[..4], &[1, 2, 3, 4]);
        storage.as_bytes_mut()[10] = 7;
        assert_eq!(storage.as_bytes()[10], 7);
    }

    #[test]
    fn aligned_bytes_rejects_non_divisible_typed_views() {
        let mut storage = AlignedBytes::with_len(3).expect("failed to initialize aligned bytes");
        assert!(storage.as_slice::<u16>().is_none());
        assert!(storage.as_slice_mut::<u16>().is_none());

        storage
            .set_len(4)
            .expect("failed to resize aligned bytes to divisible length");
        assert_eq!(
            storage.as_slice::<u16>().expect("missing typed view").len(),
            2
        );
    }
}
