//! Operating system and environment abstractions.
//!
//! This module provides traits for low-level memory operations such as
//! memory mapping (`mmap`) and memory protection (`mprotect`). It allows
//! the ELF loader to be portable across different operating systems
//! and bare-metal environments.

pub use defs::{MadviseAdvice, MapFlags, PageSize, ProtFlags};
pub(crate) use mapper::Mapper;
pub(crate) use memory::MappedView;
pub use memory::{MappedRegion, VmAddr};
pub use platform::DefaultMmap;
pub(crate) use platform::*;
pub use traits::{MappedRegionOps, Mmap, MmapResult};

mod defs;
mod mapper;
mod memory;
mod platform;
mod traits;
