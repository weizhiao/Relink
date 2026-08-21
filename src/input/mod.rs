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
        let value = NEXT_SOURCE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("module source identity space is exhausted");
        Self([Self::GENERATED, 0, 0, value as u64])
    }
}

#[cfg(test)]
mod tests {
    use super::ModuleSourceId;

    #[test]
    fn source_kinds_do_not_overlap() {
        let file = ModuleSourceId::file(7, u128::MAX);
        let opaque = ModuleSourceId::opaque(7, u128::MAX);
        let generated = ModuleSourceId::fresh();

        assert_ne!(file, opaque);
        assert_ne!(file, generated);
        assert_ne!(opaque, generated);
    }
}
