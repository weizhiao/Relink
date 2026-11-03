use alloc::vec::Vec;
use core::{
    mem,
    mem::{MaybeUninit, align_of, size_of},
};

use crate::{AlignedBytes, ByteRepr, IoError, ReadBoundsError, Result, try_cast_bytes};
use alloc::boxed::Box;

use super::{ModuleSourceId, Path};

/// A borrowed file range containing the same bytes as the ELF reader.
/// The handle must remain valid while the reader is borrowed; it is not duplicated.
///
/// `len` bounds ELF data, not page-rounded mappings. Boundary pages may expose
/// adjacent bytes. Readers needing byte-level isolation must return `None` from
/// [`ElfReader::file_backing`] and use copying.
#[derive(Clone, Copy, Debug)]
pub struct FileBacking {
    /// Borrowed platform file descriptor/handle.
    pub fd: isize,
    /// File offset corresponding to ELF offset zero.
    pub offset: usize,
    /// Number of bytes in the ELF source.
    pub len: usize,
}

/// Reads ELF bytes and metadata from files, memory, or custom storage.
pub trait ElfReader {
    /// Returns the loader source path or caller-provided source identifier.
    fn path(&self) -> &Path;

    /// Returns the total length in bytes of the ELF object source.
    fn len(&self) -> usize;

    /// Reads data from the ELF object at the given offset into the provided buffer.
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<()>;

    /// Returns an identity derived from the opened source, not a separate path lookup.
    /// Use a stable opaque ID for custom sources, or [`ModuleSourceId::fresh`] when
    /// each independently opened reader should represent a different source.
    fn source_id(&self) -> ModuleSourceId;

    /// Borrows bytes when a stable in-memory view is available.
    /// Return `Ok(None)` to make callers fall back to [`Self::read`].
    fn borrow_bytes(&self, _offset: usize, _len: usize) -> Result<Option<&[u8]>> {
        Ok(None)
    }

    /// Returns the backing range for direct page-granularity mapping.
    ///
    /// The range must describe the same source and length as this reader.
    /// Unaligned file offsets use copying. Otherwise, returning `Some` selects
    /// file mapping and requires a compatible mapping backend. Mapping errors
    /// are returned without retrying through reads. Return `None` (the default)
    /// to select copying.
    fn file_backing(&self) -> Option<FileBacking> {
        None
    }

    /// Returns the final path component of the ELF source path.
    fn file_name(&self) -> &[u8] {
        self.path().file_name()
    }
}

/// Convenience helpers for reading ELF payloads through an [`ElfReader`].
pub(crate) trait ElfReaderExt: ElfReader {
    /// Borrows bytes from the source when possible, otherwise reads them into
    /// `scratch` and returns the resulting typed view.
    #[inline]
    fn read_slice<'a, V>(
        &'a self,
        offset: usize,
        len: usize,
        scratch: &'a mut AlignedBytes,
    ) -> Result<&'a [V]>
    where
        V: ByteRepr + 'a,
    {
        if let Some(bytes) = self.borrow_bytes(offset, len)?
            && let Some(values) = try_cast_bytes::<V>(bytes)
        {
            return Ok(values);
        }

        let Some(()) = scratch.resize(len) else {
            return Err(IoError::ReadOutOfBounds(Box::new(ReadBoundsError::new(
                offset,
                len,
                self.len(),
            )))
            .into());
        };
        let bytes = scratch.as_bytes_mut();
        self.read(bytes, offset)?;
        let Some(values) = try_cast_bytes::<V>(bytes) else {
            return Err(IoError::ReadBufferNotAligned {
                align: align_of::<V>(),
            }
            .into());
        };
        Ok(values)
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

#[inline]
unsafe fn assume_init_vec<T>(mut values: Vec<MaybeUninit<T>>) -> Vec<T> {
    let len = values.len();
    let cap = values.capacity();
    let ptr = values.as_mut_ptr().cast::<T>();
    mem::forget(values);
    unsafe { Vec::from_raw_parts(ptr, len, cap) }
}

/// Converts paths, byte buffers, and existing readers into an ELF reader.
/// Existing readers pass through unchanged.
pub trait IntoElfReader {
    /// The type of reader produced by this conversion.
    type Reader: ElfReader;

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
    fn source_id(&self) -> ModuleSourceId {
        (**self).source_id()
    }

    #[inline]
    fn borrow_bytes(&self, offset: usize, len: usize) -> Result<Option<&[u8]>> {
        (**self).borrow_bytes(offset, len)
    }

    #[inline]
    fn file_backing(&self) -> Option<FileBacking> {
        (**self).file_backing()
    }
}

impl<R: ElfReader> IntoElfReader for R {
    type Reader = R;

    #[inline]
    fn into_reader(self) -> Result<Self::Reader> {
        Ok(self)
    }
}
