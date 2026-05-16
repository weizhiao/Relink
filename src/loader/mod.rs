//! Loading entry points and customization hooks.
//!
//! This module centers on [`Loader`], the main entry point for mapping ELF inputs
//! into memory. A loader reads ELF metadata, maps segments, builds raw image types,
//! and prepares them for relocation.
//!
//! It also exposes the main customization points used during loading:
//!
//! - [`LoadHook`] for observing program headers as they are mapped
//! - [`LifecycleHandler`] for customizing `.init` / `.fini` invocation
//! - `with_dynamic_initializer` for initializing dynamic-image user data
//! - `with_*` builder methods for swapping the memory-mapping backend or TLS resolver

mod buffer;
mod builder;
mod load;
mod loader;
mod traits;

pub(crate) use buffer::ElfBuf;
pub(crate) use builder::{ImageBuilder, ScanBuilder};
pub use loader::Loader;
pub(crate) use loader::LoaderInner;
pub(crate) use traits::DynLifecycleHandler;
pub use traits::{LifecycleHandler, LoadHook, LoadHookContext};
