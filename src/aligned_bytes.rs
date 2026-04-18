use alloc::{boxed::Box, vec::Vec};
use core::{
    mem::{align_of, size_of},
    ptr::NonNull,
};

/// Owned bytes backed by word-aligned storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignedBytes {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBytes {
    #[inline]
    fn required_words(byte_len: usize) -> Option<usize> {
        let word_size = size_of::<u64>();
        byte_len.checked_add(word_size - 1).map(|v| v / word_size)
    }

    pub fn with_len(byte_len: usize) -> Option<Self> {
        let words = Self::required_words(byte_len)?;
        let mut storage = Vec::new();
        storage.resize(words, 0);
        Some(Self {
            words: storage,
            len: byte_len,
        })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn set_len(&mut self, byte_len: usize) -> Option<()> {
        let words = Self::required_words(byte_len)?;
        if words > self.words.len() {
            self.words.resize(words, 0);
        }
        self.len = byte_len;
        Some(())
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }

    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
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
        try_cast_slice(self.as_ref())
    }

    #[inline]
    pub(crate) fn try_cast_slice_mut<T: ByteRepr>(&mut self) -> Option<&mut [T]> {
        try_cast_slice_mut(self.as_mut())
    }

    #[inline]
    pub(crate) fn try_for_each<T: ByteRepr, E>(
        &self,
        mut f: impl FnMut(usize, &T) -> core::result::Result<(), E>,
    ) -> Option<core::result::Result<(), E>> {
        let values = self.try_cast_slice::<T>()?;
        for (index, value) in values.iter().enumerate() {
            if let Err(err) = f(index, value) {
                return Some(Err(err));
            }
        }
        Some(Ok(()))
    }

    #[inline]
    pub(crate) fn try_for_each_mut<T: ByteRepr, E>(
        &mut self,
        mut f: impl FnMut(usize, &mut T) -> core::result::Result<(), E>,
    ) -> Option<core::result::Result<(), E>> {
        let values = self.try_cast_slice_mut::<T>()?;
        for (index, value) in values.iter_mut().enumerate() {
            if let Err(err) = f(index, value) {
                return Some(Err(err));
            }
        }
        Some(Ok(()))
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
/// - its in-memory representation matches its byte layout
pub(crate) unsafe trait ByteRepr: Sized {}

unsafe impl ByteRepr for u8 {}

#[inline]
pub(crate) fn try_cast_slice<T: ByteRepr>(bytes: &[u8]) -> Option<&[T]> {
    let elem_size = size_of::<T>();
    if elem_size == 0 {
        return None;
    }
    if bytes.is_empty() {
        return Some(unsafe { core::slice::from_raw_parts(NonNull::<T>::dangling().as_ptr(), 0) });
    }
    if !bytes.len().is_multiple_of(elem_size) {
        return None;
    }
    if !(bytes.as_ptr() as usize).is_multiple_of(align_of::<T>()) {
        return None;
    }
    Some(unsafe {
        core::slice::from_raw_parts(bytes.as_ptr().cast::<T>(), bytes.len() / elem_size)
    })
}

#[inline]
pub(crate) fn try_cast_slice_mut<T: ByteRepr>(bytes: &mut [u8]) -> Option<&mut [T]> {
    let elem_size = size_of::<T>();
    if elem_size == 0 {
        return None;
    }
    if bytes.is_empty() {
        return Some(unsafe {
            core::slice::from_raw_parts_mut(NonNull::<T>::dangling().as_ptr(), 0)
        });
    }
    if !bytes.len().is_multiple_of(elem_size) {
        return None;
    }
    if !(bytes.as_ptr() as usize).is_multiple_of(align_of::<T>()) {
        return None;
    }
    Some(unsafe {
        core::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<T>(), bytes.len() / elem_size)
    })
}
