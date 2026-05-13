//! Shared core state for loaded ELF images.
//!
//! The types in this module back the public image wrappers exposed from
//! [`crate::image`]. They store metadata, symbol tables, mapped segments,
//! lifecycle handlers, TLS state, and dependency ownership.

mod handle;
mod loaded;
mod symbol;

pub(crate) use handle::CoreInner;
pub use handle::{ElfCore, ElfCoreRef};
pub use loaded::LoadedCore;
pub use symbol::Symbol;
