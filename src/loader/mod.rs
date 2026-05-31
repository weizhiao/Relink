//! Loading entry points and customization hooks.
//!
//! This module centers on [`Loader`], the main entry point for mapping ELF inputs
//! into memory. A loader reads ELF metadata, maps segments, builds raw image types,
//! and prepares them for relocation.
//!
//! It also exposes the main customization points used during loading:
//!
//! - [`crate::observer::LoadObserver`] for observing program headers and loaded dynamic images
//! - [`crate::observer::RelocationObserver`] events for lifecycle and relocation customization
//! - `with_data` for selecting dynamic-image user data
//! - `with_*` builder methods for swapping the memory-mapping backend or TLS resolver

mod buffer;
mod builder;
mod load;
mod loader;

pub(crate) use buffer::ElfBuf;
pub(crate) use builder::{ImageBuilder, ScanBuilder};
#[cfg(feature = "object")]
pub(crate) use load::ExpectedElf;
pub use loader::Loader;
pub(crate) use loader::LoaderInner;
