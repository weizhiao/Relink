use alloc::vec::Vec;
use core::{
    mem,
    mem::{MaybeUninit, align_of, size_of},
};

use crate::{AlignedBytes, ByteRepr, IoError, ReadBoundsError, Result, try_cast_bytes};
use alloc::boxed::Box;

use super::Path;

/// A trait for reading ELF data from various sources.
///
/// `ElfReader` abstracts the underlying storage (memory, file system, etc.)
/// providing a unified interface for the loader to access ELF headers and segments.
pub trait ElfReader {
    /// Returns the loader source path or caller-provided source identifier.
    fn path(&self) -> &Path;

    /// Returns the total length in bytes of the ELF object source.
    fn len(&self) -> usize;

    /// Reads data from the ELF object at the given offset into the provided buffer.
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<()>;

    /// Borrows bytes directly from the ELF object when the backend can provide
    /// a stable in-memory view.
    ///
    /// Backends that cannot expose borrowed bytes return `Ok(None)`. Callers
    /// should fall back to [`ElfReader::read`] in that case.
    fn borrow_bytes(&self, _offset: usize, _len: usize) -> Result<Option<&[u8]>> {
        Ok(None)
    }

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
    /// Borrows bytes from the source when possible, otherwise reads them into
    /// `scratch`, casts them to `V`, and passes the resulting view to `f`.
    #[inline]
    fn with_bytes<'a, V, S, T>(
        &'a self,
        offset: usize,
        len: usize,
        scratch: &'a mut S,
        f: impl FnOnce(&'a [V]) -> Result<T>,
    ) -> Result<T>
    where
        V: ByteRepr + 'a,
        S: ByteScratch + ?Sized,
    {
        if let Some(bytes) = self.borrow_bytes(offset, len)?
            && let Some(values) = try_cast_bytes::<V>(bytes)
        {
            return f(values);
        }

        let Some(bytes) = scratch.resize_bytes(len) else {
            return Err(IoError::ReadOutOfBounds(Box::new(ReadBoundsError::new(
                offset,
                len,
                self.len(),
            )))
            .into());
        };
        self.read(bytes, offset)?;
        let Some(values) = try_cast_bytes::<V>(bytes) else {
            return Err(IoError::ReadBufferNotAligned {
                align: align_of::<V>(),
            }
            .into());
        };
        f(values)
    }

    /// Reads values from the underlying object into a new vector.
    #[inline]
    fn read_to_vec<T: ByteRepr>(&self, offset: usize, count: usize) -> Result<Vec<T>> {
        let byte_len = count
            .checked_mul(size_of::<T>())
            .ok_or(IoError::ReadBufferTooLarge)?;
        let mut values = Vec::<MaybeUninit<T>>::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| IoError::OutOfMemory)?;
        unsafe {
            values.set_len(count);
        }
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(values.as_mut_ptr().cast::<u8>(), byte_len) };
        self.read(bytes, offset)?;
        Ok(unsafe { assume_init_vec(values) })
    }
}

impl<T: ElfReader + ?Sized> ElfReaderExt for T {}

pub(crate) trait ByteScratch {
    fn resize_bytes(&mut self, len: usize) -> Option<&mut [u8]>;
}

impl ByteScratch for AlignedBytes {
    #[inline]
    fn resize_bytes(&mut self, len: usize) -> Option<&mut [u8]> {
        self.resize(len)?;
        Some(self.as_bytes_mut())
    }
}

impl ByteScratch for Vec<u8> {
    #[inline]
    fn resize_bytes(&mut self, len: usize) -> Option<&mut [u8]> {
        self.resize(len, 0);
        Some(self.as_mut_slice())
    }
}

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
    fn len(&self) -> usize {
        (**self).len()
    }

    #[inline]
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        (**self).read(buf, offset)
    }

    #[inline]
    fn borrow_bytes(&self, offset: usize, len: usize) -> Result<Option<&[u8]>> {
        (**self).borrow_bytes(offset, len)
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
