//! ELF input traits and built-in data sources.
//!
//! Loading APIs accept any [`IntoElfReader`] input. This lets callers pass file paths,
//! memory buffers, or explicit reader types without changing the loading logic.
//!
//! Supported inputs include:
//!
//! - [`ElfFile`] for file-backed ELF objects
//! - [`Path`] / [`PathBuf`] for file path values used by file-backed inputs
//! - [`ElfBinary`] for named byte slices already resident in memory
//! - [`IntoElfReader`] conversions for `&str`, `String`, `&[u8]`, and `&Vec<u8>`
//! - any existing [`ElfReader`], passed through unchanged

/// Immutable shared paths retained by loaded modules and C interface metadata.
pub use module_path::ModulePath;

pub(crate) use backend::{BufferedElfFile, checked_read_range as check_read_range};
pub use backend::{ElfBinary, ElfFile};
pub use path::{Path, PathBuf, PathStr, PathString};
pub(crate) use traits::ElfReaderExt;
pub use traits::{ElfReader, FileBacking, IntoElfReader};

mod backend;
mod module_path;
mod path;
mod traits;

use crate::sync::{AtomicUsize, Ordering};

static NEXT_SOURCE_ID: AtomicUsize = AtomicUsize::new(1);

/// Stable identity of the source backing one module.
///
/// File-backed readers derive this from the opened handle, so different paths,
/// hard links, and symbolic links to the same file compare equal. Memory,
/// synthetic, and remote sources may provide an opaque caller-defined identity.
/// The representation is intentionally opaque; consumers should only compare,
/// order, or hash it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleSourceId([u64; 4]);

impl ModuleSourceId {
    const FILE: u64 = 0;
    const OPAQUE: u64 = 1;
    const GENERATED: u64 = 2;

    /// Creates an identity for a file within a storage volume.
    #[inline]
    pub const fn file(volume: u64, file: u128) -> Self {
        Self([Self::FILE, volume, (file >> 64) as u64, file as u64])
    }

    /// Creates a stable identity in a caller-defined namespace.
    ///
    /// Callers must ensure that `(namespace, value)` uniquely identifies one
    /// source for as long as it may be present in a link context.
    #[inline]
    pub const fn opaque(namespace: u64, value: u128) -> Self {
        Self([Self::OPAQUE, namespace, (value >> 64) as u64, value as u64])
    }

    /// Creates a fresh process-local identity for an anonymous source.
    #[inline]
    pub fn fresh() -> Self {
        #[allow(deprecated)]
        let value = NEXT_SOURCE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("module source identity space is exhausted");
        Self([Self::GENERATED, 0, 0, value as u64])
    }
}
