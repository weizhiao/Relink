//! Lazy PLT binding support.
//!
//! The [`LazyBinder`] trait lets callers install target-specific lazy binding
//! entries. With the `lazy-binding` feature enabled, `NativeLazyBinder` provides
//! the same-process native binder used for ordinary host execution.

mod defs;
#[cfg(feature = "lazy-binding")]
mod native;
mod traits;

pub use defs::{LazyPlacement, LazyPltReloc, LazyRuntime, LazySetup, LazySlots, LazyValues};
#[cfg(feature = "lazy-binding")]
pub use native::NativeLazyBinder;
#[cfg(feature = "lazy-binding")]
pub(crate) use native::dl_fixup;
pub use traits::{LazyBinder, SupportLazy};
pub(crate) use traits::{prepare_plt, relocate_jump_slot};
