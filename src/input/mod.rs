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
