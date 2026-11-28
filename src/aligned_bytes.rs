use alloc::vec::Vec;
use core::mem::size_of;

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct AlignedWord {
    _bytes: [u8; 8],
}

/// Reusable, word-aligned scratch space for reading ELF records.
#[derive(Default)]
pub(crate) struct AlignedBytes {
    words: Vec<AlignedWord>,
}

impl AlignedBytes {
    pub(crate) fn resize(&mut self, byte_len: usize) -> Option<&mut [u8]> {
        let word_len = byte_len.div_ceil(size_of::<AlignedWord>());
        if word_len > isize::MAX as usize / size_of::<AlignedWord>() {
            return None;
        }
        self.words.resize(word_len, AlignedWord::default());
        // AlignedWord contains eight initialized bytes with no padding.
        Some(unsafe { core::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), byte_len) })
    }
}

#[inline]
pub(crate) fn try_cast_bytes<T: ByteRepr>(bytes: &[u8]) -> Option<&[T]> {
    if size_of::<T>() == 0 {
        return None;
    }

    let (prefix, values, suffix) = unsafe { bytes.align_to::<T>() };
    if prefix.is_empty() && suffix.is_empty() {
        Some(values)
    } else {
        None
    }
}

/// Types that can be safely viewed from arbitrary bytes.
///
/// # Safety
/// Implementors must be plain data:
/// - every bit pattern is a valid value
/// - the type has no drop glue
/// - its in-memory representation matches its byte layout, with no padding
///   bytes that may be uninitialized
///
/// This trait only describes memory validity and layout. It does not imply
/// that multi-byte fields have any particular endian interpretation.
pub unsafe trait ByteRepr: Sized {}

macro_rules! impl_byte_repr {
    ($($ty:ty),+ $(,)?) => {
        $(unsafe impl ByteRepr for $ty {})+
    };
}

impl_byte_repr!(
    u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize, f32, f64,
);

unsafe impl<T: ByteRepr, const N: usize> ByteRepr for [T; N] {}
