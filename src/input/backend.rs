use super::{ElfReader, IntoElfReader};
use crate::{Result, os::RawFile};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// An ELF object source backed by an in-memory byte slice.
///
/// This is useful for loading ELF files that are already in memory, such as
/// those embedded in the binary or received over a network.
#[derive(Debug)]
pub struct ElfBinary<'bytes> {
    /// The name assigned to this ELF object.
    name: String,
    /// The raw ELF data.
    bytes: &'bytes [u8],
}

impl<'bytes> ElfBinary<'bytes> {
    /// Creates a new memory-based ELF object.
    ///
    /// This constructor creates an [`ElfBinary`] instance from a byte slice
    /// containing the ELF data and a name for the object.
    ///
    /// # Arguments
    /// - `name` - A string identifier for the ELF object, typically the
    ///            original file path. Used for error reporting and debugging.
    /// - `bytes` - A byte slice containing the complete ELF data.
    ///
    /// # Returns
    /// A new [`ElfBinary`] instance.
    ///
    /// # Examples
    /// ```rust
    /// use elf_loader::input::ElfBinary;
    ///
    /// let data = &[]; // In practice, this would be the bytes of an ELF file
    /// let binary = ElfBinary::new("liba.so", data);
    /// ```
    pub fn new(name: &str, bytes: &'bytes [u8]) -> Self {
        Self {
            name: name.to_string(),
            bytes,
        }
    }
}

impl<'bytes> ElfReader for ElfBinary<'bytes> {
    /// Returns the name of the ELF binary.
    fn file_name(&self) -> &str {
        &self.name
    }

    /// Reads data from the memory-based ELF object.
    ///
    /// This implementation directly copies data from the in-memory byte slice
    /// to the provided buffer, making it very efficient.
    ///
    /// # Arguments
    /// - `buf` - A mutable slice where the read data will be stored.
    /// - `offset` - The byte offset within the ELF data where reading begins.
    ///
    /// # Returns
    /// - `Ok(())` - If the read operation was successful.
    /// - `Err` - If the read operation would go beyond the available data.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> crate::Result<()> {
        buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
        Ok(())
    }

    /// Returns `None` since memory-based objects don't have file descriptors.
    fn as_fd(&self) -> Option<isize> {
        None
    }
}

/// An ELF object source backed by a file on the filesystem.
///
/// This implementation uses standard file I/O to read ELF data. It also
/// provides access to the underlying file descriptor for memory mapping.
pub struct ElfFile {
    /// The underlying OS-specific file handle.
    inner: RawFile,
}

impl ElfFile {
    /// Creates a new file-based ELF object from an owned file descriptor.
    ///
    /// # Safety
    /// The caller must ensure that:
    /// - The `raw_fd` parameter is a valid, open file descriptor.
    /// - The file descriptor is owned by this object and will not be closed
    ///   by any other code while this object exists.
    /// - The file contains valid ELF data.
    ///
    /// # Arguments
    /// - `path` - The file path, used for identification and error reporting.
    /// - `raw_fd` - The raw file descriptor for the open ELF file.
    ///
    /// # Returns
    /// A new [`ElfFile`] instance.
    pub unsafe fn from_owned_fd(path: &str, raw_fd: i32) -> Self {
        ElfFile {
            inner: RawFile::from_owned_fd(path, raw_fd),
        }
    }

    /// Creates a new file-based ELF object by opening a file at the given path.
    ///
    /// This constructor opens the file at the specified path and prepares it
    /// for use as an ELF object. The file is automatically closed when the
    /// [`ElfFile`] instance is dropped.
    ///
    /// # Arguments
    /// - `path` - The path to the ELF file to open.
    ///
    /// # Returns
    /// - `Ok(ElfFile)` - If the file was successfully opened and is accessible.
    /// - `Err` - If the file could not be opened or accessed.
    pub fn from_path(path: impl AsRef<str>) -> Result<Self> {
        let path = path.as_ref();
        #[cfg(feature = "log")]
        log::debug!("Opening ELF file: {}", path);

        let inner = RawFile::from_path(path).map_err(|e| {
            #[cfg(feature = "log")]
            log::error!("Failed to open ELF file {}: {:?}", path, e);
            e
        })?;

        Ok(ElfFile { inner })
    }
}

impl ElfReader for ElfFile {
    /// Returns the name of the ELF file.
    fn file_name(&self) -> &str {
        self.inner.file_name()
    }

    /// Reads data from the file-based ELF object.
    ///
    /// This implementation reads data from the underlying file using standard
    /// file I/O operations. For better performance with large files, consider
    /// using memory mapping when possible.
    ///
    /// # Arguments
    /// - `buf` - A mutable slice where the read data will be stored.
    /// - `offset` - The byte offset within the file where reading begins.
    ///
    /// # Returns
    /// - `Ok(())` - If the read operation was successful.
    /// - `Err` - If the read operation failed (e.g., I/O error, invalid offset).
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        self.inner.read(buf, offset)
    }

    /// Returns the raw file descriptor for the underlying file.
    ///
    /// This enables memory mapping optimizations when available, as the
    /// file descriptor can be used directly with mmap-like operations.
    fn as_fd(&self) -> Option<isize> {
        self.inner.as_fd()
    }
}

// Implementation of `ElfReader` for byte slices.
//
// This allows users to pass a byte slice directly to loading functions
// for in-memory ELF data.
impl<'a> ElfReader for &'a [u8] {
    /// Returns a generic name for memory-based data.
    fn file_name(&self) -> &str {
        "<memory>"
    }

    /// Reads data from the byte slice at the specified offset.
    ///
    /// # Arguments
    /// - `buf` - A mutable slice where the read data will be stored.
    /// - `offset` - The byte offset within the slice where reading begins.
    ///
    /// # Returns
    /// - `Ok(())` - If the read operation was successful.
    /// - `Err` - If the offset is out of bounds.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        if offset + buf.len() > self.len() {
            return Err(crate::Error::Io {
                msg: "read offset out of bounds".into(),
            });
        }
        buf.copy_from_slice(&self[offset..offset + buf.len()]);
        Ok(())
    }

    /// Memory-based readers do not have file descriptors.
    fn as_fd(&self) -> Option<isize> {
        None
    }
}

// Implementation for string slices (file paths)
impl<'a> IntoElfReader<'a> for &'a str {
    type Reader = ElfFile;

    fn into_reader(self) -> Result<Self::Reader> {
        ElfFile::from_path(self)
    }
}

// Implementation for owned strings (file paths)
impl<'a> IntoElfReader<'a> for String {
    type Reader = ElfFile;

    fn into_reader(self) -> Result<Self::Reader> {
        ElfFile::from_path(&self)
    }
}

// Implementation for byte slices (in-memory ELF data)
impl<'a> IntoElfReader<'a> for &'a [u8] {
    type Reader = ElfBinary<'a>;

    fn into_reader(self) -> Result<Self::Reader> {
        Ok(ElfBinary::new("<memory>", self))
    }
}

impl<'a> IntoElfReader<'a> for &'a Vec<u8> {
    type Reader = ElfBinary<'a>;

    fn into_reader(self) -> Result<Self::Reader> {
        Ok(ElfBinary::new("<memory>", self.as_slice()))
    }
}

// Implementation for already constructed ElfFile (pass-through)
impl<'a> IntoElfReader<'a> for ElfFile {
    type Reader = ElfFile;

    fn into_reader(self) -> Result<Self::Reader> {
        Ok(self)
    }
}

// Implementation for already constructed ElfBinary (pass-through)
impl<'a, 'b> IntoElfReader<'a> for ElfBinary<'b>
where
    'b: 'a,
{
    type Reader = ElfBinary<'b>;

    fn into_reader(self) -> Result<Self::Reader> {
        Ok(self)
    }
}
