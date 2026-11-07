//! Loading entry points and customization hooks.
//!
//! [`Loader`] configures the architecture, memory mapper, and image user data.
//! Bind a [`crate::Domain`] with [`Loader::run`] to scan or map an ELF input.
//! The domain supplies the executor and optional TLS resolver.
//!
//! Attach a [`crate::observer::LoadObserver`] through [`LoaderRun::with_observer`]
//! to inspect loading events. Pass mapped images to [`crate::Relocator`] for
//! relocation and lifecycle customization.

mod builder;
mod defs;
mod loader;
mod run;

pub(crate) use builder::{ImageBuilder, ScanBuilder};
pub(crate) use defs::{ElfBuf, ExpectedElf, read_ehdr};
pub use loader::Loader;
pub use run::LoaderRun;
