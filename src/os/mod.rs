//! Operating system and environment abstractions.
//!
//! This module provides traits for low-level platform operations such as
//! memory mapping (`mmap`). It allows the ELF loader to be portable across
//! different operating systems and bare-metal environments.

pub use defs::{MadviseAdvice, MapFlags, PageSize, ProtFlags};
pub use platform::DefaultMmap;
pub(crate) use platform::*;
pub use traits::Mmap;

mod defs;
mod platform;
mod traits;
