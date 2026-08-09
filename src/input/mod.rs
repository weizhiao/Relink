//! ELF input traits and built-in data sources.
//!
//! Loading APIs accept any [`IntoElfReader`] input. This lets callers pass file paths,
//! memory buffers, or explicit reader types without changing the loading logic.
//!
//! The built-in concrete inputs are:
//!
//! - [`ElfFile`] for file-backed ELF objects
//! - [`Path`] / [`PathBuf`] for file path values used by file-backed inputs
//! - [`ElfBinary`] for named byte slices already resident in memory
//! - blanket [`IntoElfReader`] implementations for `&str`, `String`, `&[u8]`, and `&Vec<u8>`

pub use backend::{ElfBinary, ElfFile};
pub use path::{Path, PathBuf};
pub(crate) use traits::ElfReaderExt;
pub use traits::{ElfReader, IntoElfReader};

mod backend;
mod path;
mod traits;

/// Stable identity of one file within a storage volume.
///
/// File-backed readers derive this from the opened handle, so different paths,
/// hard links, and symbolic links to the same file compare equal. Custom
/// readers may provide their own volume and file values through [`FileId::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId {
    volume: u64,
    file_high: u64,
    file_low: u64,
}

impl FileId {
    /// Creates a file identity from backend-defined volume and file values.
    #[inline]
    pub const fn new(volume: u64, file: u128) -> Self {
        Self {
            volume,
            file_high: (file >> 64) as u64,
            file_low: file as u64,
        }
    }
}
