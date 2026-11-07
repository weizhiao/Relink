//! Memory mapping, page protection, and platform backends.
//!
//! [`Mmap`] creates and populates regions accessed through [`crate::memory`].
//! Use [`DefaultMmap`] for the current platform, [`AllocMmap`] for allocator-backed
//! storage, or [`FixedMmap`] for caller-provided storage.

pub use defs::{MadviseAdvice, MapFlags, PageSize, ProtFlags, ThpPolicy};
pub use mmap::{AllocMmap, FixedMmap};
pub use platform::DefaultMmap;
pub(crate) use platform::*;
pub use traits::{Mmap, SpaceInit, SpaceLayout};

mod defs;
mod mmap;
mod platform;
mod traits;
