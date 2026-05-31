//! Operating system and environment abstractions.
//!
//! This module provides traits for low-level memory operations such as
//! memory mapping (`mmap`) and memory protection (`mprotect`). It allows
//! the ELF loader to be portable across different operating systems
//! and bare-metal environments.

pub use code::{CodeContext, CodeExecutor, NativeCodeExecutor};
pub use defs::{MadviseAdvice, MapFlags, PageSize, ProtFlags};
pub use memory::{HostRegion, MappedRegion, RegionAccess, VmAddr, VmOffset};
pub(crate) use memory::{MappedView, align_up, rounddown, roundup};
pub use platform::DefaultMmap;
pub(crate) use platform::*;
pub use traits::Mmap;

mod code;
mod defs;
mod memory;
mod platform;
mod traits;
