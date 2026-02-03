//! ELF input abstraction and data sources.
//!
//! This module provides traits and implementations for accessing ELF data
//! from diverse sources, such as files in a filesystem or byte buffers in memory.
//! It abstracts the reading mechanism to allow the loader to operate
//! uniformly regardless of how the ELF data is stored.

pub use backend::{ElfBinary, ElfFile};
pub use traits::{ElfReader, IntoElfReader};

mod backend;
mod traits;
