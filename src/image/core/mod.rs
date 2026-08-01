//! Shared core state for loaded ELF images.
//!
//! The types in this module back the public image wrappers exposed from
//! [`crate::image`]. They store metadata, runtime exports, mapped segments,
//! lifecycle handlers, TLS state, and dependency ownership.

mod defs;
mod handle;
mod loaded;

pub use defs::Symbol;
pub(crate) use defs::{CoreInner, CoreRuntime};
pub use handle::{ElfCore, ElfCoreRef};
pub use loaded::LoadedCore;
