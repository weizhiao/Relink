use alloc::{boxed::Box, vec::Vec};
use core::mem::size_of;

/// Owned bytes backed by word-aligned storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlignedBytes {
    words: Vec<u64>,
    len: usize,
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
            len: byte_len,
        })
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn set_len(&mut self, byte_len: usize) -> Option<()> {
        let words = Self::required_words(byte_len)?;
        if words > self.words.len() {
            self.words.resize(words, 0);
        }
        self.len = byte_len;
        Some(())
    }

    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }

    #[inline]
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.len) }
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut aligned =
            Self::with_len(bytes.len()).expect("slice length overflow when building AlignedBytes");
        aligned.as_bytes_mut().copy_from_slice(bytes);
        aligned
    }

    #[inline]
    pub(crate) fn try_cast_slice<T: ByteRepr>(&self) -> Option<&[T]> {
        if size_of::<T>() == 0 {
            return None;
        }

        let (prefix, values, suffix) = unsafe { self.as_bytes().align_to::<T>() };
        if prefix.is_empty() && suffix.is_empty() {
            Some(values)
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn try_cast_slice_mut<T: ByteRepr>(&mut self) -> Option<&mut [T]> {
        if size_of::<T>() == 0 {
            return None;
        }

        let (prefix, values, suffix) = unsafe { self.as_bytes_mut().align_to_mut::<T>() };
        if prefix.is_empty() && suffix.is_empty() {
            Some(values)
        } else {
            None
        }
    }
}

impl AsRef<[u8]> for AlignedBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for AlignedBytes {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

impl From<Vec<u8>> for AlignedBytes {
    #[inline]
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(&bytes)
    }
}

impl From<Box<[u8]>> for AlignedBytes {
    #[inline]
    fn from(bytes: Box<[u8]>) -> Self {
        Self::from_bytes(&bytes)
    }
}

impl<const N: usize> From<[u8; N]> for AlignedBytes {
    #[inline]
    fn from(bytes: [u8; N]) -> Self {
        Self::from_bytes(&bytes)
    }
}

/// Types that can be safely overwritten from arbitrary bytes.
///
/// # Safety
/// Implementors must be plain data:
/// - every bit pattern is a valid value
/// - the type has no drop glue
/// - its in-memory representation matches its byte layout, with no padding
///   bytes that may be uninitialized
pub(crate) unsafe trait ByteRepr: Sized {}

unsafe impl ByteRepr for u8 {}
