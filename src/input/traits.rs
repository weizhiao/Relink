use alloc::vec::Vec;
use core::mem::size_of;

use crate::Result;

/// A trait for reading ELF data from various sources.
///
/// `ElfReader` abstracts the underlying storage (memory, file system, etc.)
/// providing a unified interface for the loader to access ELF headers and segments.
pub trait ElfReader {
    /// Returns the full name or path of the ELF object.
    fn file_name(&self) -> &str;

    /// Reads data from the ELF object at the given offset into the provided buffer.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()>;

    /// Returns the underlying file descriptor if the source is a file.
    ///
    /// This is used by the loader to perform efficient memory mapping (`mmap`).
    /// Returns `None` for memory-based sources.
    fn as_fd(&self) -> Option<isize>;

    /// Returns the short name of the ELF object (the filename without the path).
    fn shortname(&self) -> &str {
        let name = self.file_name();
        name.rsplit('/').next().unwrap_or(name)
    }
}

/// Convenience helpers for reading ELF payloads through an [`ElfReader`].
pub(crate) trait ElfReaderExt: ElfReader {
    /// Reads values from the underlying object into a new vector.
    #[inline]
    fn read_to_vec<T>(&mut self, offset: usize, count: usize) -> Result<Vec<T>> {
        let mut values = Vec::<T>::with_capacity(count);
        unsafe {
            values.set_len(count);
        }
        self.read_slice(&mut values, offset)?;
        Ok(values)
    }

    /// Reads raw bytes into an existing typed slice.
    #[inline]
    fn read_slice<T>(&mut self, buf: &mut [T], offset: usize) -> Result<()> {
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
