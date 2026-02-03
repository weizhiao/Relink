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
