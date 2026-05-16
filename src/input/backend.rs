use super::{ElfReader, IntoElfReader, Path, PathBuf};
use crate::{Result, logging, os::RawFile};
use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};

/// An ELF object source backed by an in-memory byte slice.
///
/// This is useful for loading ELF files that are already in memory, such as
/// those embedded in the binary or received over a network.
#[derive(Debug)]
pub struct ElfBinary<'bytes> {
    /// Loader source path or caller-provided source identifier.
    path: PathBuf,
    /// The raw ELF data.
    bytes: Cow<'bytes, [u8]>,
}

impl<'bytes> ElfBinary<'bytes> {
    /// Creates a new memory-based ELF object from a byte slice.
    ///
    /// # Examples
    /// ```rust
    /// use elf_loader::input::ElfBinary;
    ///
    /// let data = &[]; // In practice, this would be the bytes of an ELF file
    /// let binary = ElfBinary::new("liba.so", data);
    /// ```
    pub fn new(path: impl Into<PathBuf>, bytes: &'bytes [u8]) -> Self {
        Self {
            path: path.into(),
            bytes: Cow::Borrowed(bytes),
        }
    }

    /// Creates a new memory-based ELF object that owns its bytes.
    ///
    /// This is useful for scanned images, which retain their reader until the
    /// later mapping phase.
    pub fn owned(path: impl Into<PathBuf>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: Cow::Owned(bytes.into()),
        }
    }
}

impl<'bytes> ElfReader for ElfBinary<'bytes> {
    /// Returns the source path or caller-provided identifier.
    fn path(&self) -> &Path {
        &self.path
    }

    /// Reads data from the memory-based ELF object.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> crate::Result<()> {
        let bytes = self.bytes.as_ref();
        if offset + buf.len() > bytes.len() {
            return Err(
                crate::IoError::ReadOutOfBounds(Box::new(crate::ReadBoundsError::new(
                    offset,
                    buf.len(),
                    bytes.len(),
                )))
                .into(),
            );
        }
        buf.copy_from_slice(&bytes[offset..offset + buf.len()]);
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
    /// The caller must ensure that `raw_fd` is valid and owned by this object.
    pub unsafe fn from_owned_fd(path: impl AsRef<Path>, raw_fd: i32) -> Self {
        let path = path.as_ref();
        ElfFile {
            inner: RawFile::from_owned_fd(path, raw_fd),
        }
    }

    /// Creates a new file-based ELF object by opening a file at the given path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        logging::debug!("Opening ELF file: {}", path);

        let inner = RawFile::from_path(path)?;
        Ok(ElfFile { inner })
    }
}

impl ElfReader for ElfFile {
    /// Returns the path of the ELF file.
    fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Reads data from the file-based ELF object.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        self.inner.read(buf, offset)
    }

    /// Returns the raw file descriptor for the underlying file.
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
    fn path(&self) -> &Path {
        Path::new("<memory>")
    }

    /// Reads data from the byte slice at the specified offset.
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        if offset + buf.len() > self.len() {
            return Err(
                crate::IoError::ReadOutOfBounds(Box::new(crate::ReadBoundsError::new(
                    offset,
                    buf.len(),
                    self.len(),
                )))
                .into(),
            );
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
        ElfFile::from_path(self)
    }
}

impl<'a> IntoElfReader<'a> for &'a Path {
    type Reader = ElfFile;

    fn into_reader(self) -> Result<Self::Reader> {
        ElfFile::from_path(self)
    }
}

impl<'a> IntoElfReader<'a> for PathBuf {
    type Reader = ElfFile;

    fn into_reader(self) -> Result<Self::Reader> {
        ElfFile::from_path(self)
    }
}

impl<'a> IntoElfReader<'a> for &'a PathBuf {
    type Reader = ElfFile;

    fn into_reader(self) -> Result<Self::Reader> {
        ElfFile::from_path(self)
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

impl<'a> IntoElfReader<'a> for Vec<u8> {
    type Reader = ElfBinary<'static>;

    fn into_reader(self) -> Result<Self::Reader> {
        Ok(ElfBinary::owned("<memory>", self))
    }
}

impl<'a> IntoElfReader<'a> for Box<[u8]> {
    type Reader = ElfBinary<'static>;

    fn into_reader(self) -> Result<Self::Reader> {
        Ok(ElfBinary::owned("<memory>", self.into_vec()))
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
