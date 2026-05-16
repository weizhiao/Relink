use alloc::vec::Vec;
use core::{
    mem,
    mem::{MaybeUninit, size_of},
};

use crate::{ByteRepr, Result};
use alloc::boxed::Box;

use super::Path;

/// A trait for reading ELF data from various sources.
///
/// `ElfReader` abstracts the underlying storage (memory, file system, etc.)
/// providing a unified interface for the loader to access ELF headers and segments.
pub trait ElfReader {
    /// Returns the loader source path or caller-provided source identifier.
    fn path(&self) -> &Path;

    /// Reads data from the ELF object at the given offset into the provided buffer.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()>;

    /// Returns the underlying file descriptor if the source is a file.
    ///
    /// This is used by the loader to perform efficient memory mapping (`mmap`).
    /// Returns `None` for memory-based sources.
    fn as_fd(&self) -> Option<isize>;

    /// Returns the final path component of the ELF source path.
    fn file_name(&self) -> &str {
        self.path().file_name()
    }
}

/// Convenience helpers for reading ELF payloads through an [`ElfReader`].
pub(crate) trait ElfReaderExt: ElfReader {
    /// Reads values from the underlying object into a new vector.
    #[inline]
    fn read_to_vec<T: ByteRepr>(&mut self, offset: usize, count: usize) -> Result<Vec<T>> {
        let byte_len = count
            .checked_mul(size_of::<T>())
            .expect("ElfReaderExt::read_to_vec length overflow");
        let mut values = Vec::<MaybeUninit<T>>::with_capacity(count);
        unsafe {
            values.set_len(count);
        }
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(values.as_mut_ptr().cast::<u8>(), byte_len) };
        self.read(bytes, offset)?;
        Ok(unsafe { assume_init_vec(values) })
    }

    /// Reads raw bytes into an existing typed slice.
    #[inline]
    fn read_slice<T: ByteRepr>(&mut self, buf: &mut [T], offset: usize) -> Result<()> {
        let byte_len = buf
            .len()
            .checked_mul(size_of::<T>())
            .expect("ElfReaderExt::read_slice length overflow");
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), byte_len) };
        self.read(bytes, offset)
    }
}

impl<T: ElfReader + ?Sized> ElfReaderExt for T {}

#[inline]
unsafe fn assume_init_vec<T>(mut values: Vec<MaybeUninit<T>>) -> Vec<T> {
    let len = values.len();
    let cap = values.capacity();
    let ptr = values.as_mut_ptr().cast::<T>();
    mem::forget(values);
    unsafe { Vec::from_raw_parts(ptr, len, cap) }
}

/// A trait for converting various input sources into an `ElfReader`.
///
/// This trait allows different types (like file paths or byte slices) to be
/// converted into a reader that implements `ElfReader`, enabling polymorphic
/// loading of ELF objects.
pub trait IntoElfReader<'a> {
    /// The type of reader produced by this conversion.
    type Reader: ElfReader + 'a;

    /// Converts the input into an `ElfReader`.
    ///
    /// # Returns
    /// * `Ok(reader)` - The converted reader.
    /// * `Err(error)` - If the conversion fails (e.g., file not found).
    fn into_reader(self) -> Result<Self::Reader>;
}

impl<R: ElfReader + ?Sized> ElfReader for Box<R> {
    #[inline]
    fn path(&self) -> &Path {
        (**self).path()
    }

    #[inline]
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        (**self).read(buf, offset)
    }

    #[inline]
    fn as_fd(&self) -> Option<isize> {
        (**self).as_fd()
    }
}

impl<'a, R> IntoElfReader<'a> for Box<R>
where
    R: ElfReader + 'a + ?Sized,
{
    type Reader = Box<R>;

    #[inline]
    fn into_reader(self) -> Result<Self::Reader> {
        Ok(self)
    }
}
