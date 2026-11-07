//! # Relink
//!
//! Relink is a `no_std`-friendly ELF loader and runtime linker for Rust.
//! It maps ELF images from files or memory, performs relocations at runtime, and exposes
//! typed symbol lookups with Rust lifetimes.
//!
//! ## Start with [`Loader`]
//!
//! Bind a runtime domain with [`Loader::run`] before loading an image.
//!
//! - Use [`LoaderRun::load`] to auto-detect whether the input is a dylib, executable, or
//!   relocatable object.
//! - Use [`LoaderRun::load_dylib`] or [`LoaderRun::load_exec`] when you want strict type checks.
//! - Use [`LoaderRun::load_dynamic`] when you want any `PT_DYNAMIC` image, including a dynamic
//!   `ET_EXEC`.
//! - Use [`LoaderRun::scan`] and [`LoaderRun::load_scanned_dynamic`] to split dynamic metadata
//!   discovery from mapping.
//! - Use `LoaderRun::load_object` to load `ET_REL` object files when the `object` feature is enabled.
//! - Inputs can come from file paths, [`input::Path`] / [`input::PathBuf`], raw bytes,
//!   [`input::ElfFile`], or [`input::ElfBinary`].
//!
//! Typed symbols borrow their loaded image. Use [`RelocatorRun::with_modules`] or
//! [`LocalScope`] to resolve references against other ELF images and synthetic modules.
//!
//! ## Example
//!
//! ```rust,no_run
//! use elf_loader::{
//!     Loader, Relocator, Result,
//!     AddressSpaceId, Domain,
//!     image::{SyntheticSymbol, SyntheticModule},
//! };
//!
//! extern "C" fn host_double(value: i32) -> i32 {
//!     value * 2
//! }
//!
//! fn main() -> Result<()> {
//!     let domain = Domain::native(AddressSpaceId::PROCESS);
//!     let host = SyntheticModule::new(
//!         &domain,
//!         "__host",
//!         [SyntheticSymbol::function(c"host_double", host_double as *const ())],
//!     );
//!
//!     let lib = Relocator::new()
//!         .run(Loader::new().run(domain).load_dylib("path/to/plugin.so")?)
//!         .with_modules([host])?
//!         .relocate()?;
//!
//!     let run = unsafe {
//!         lib.get::<extern "C" fn(i32) -> i32>("run")?
//!             .expect("symbol `run` not found")
//!     };
//!     assert_eq!(run(21), 42);
//!     Ok(())
//! }
//! ```
//!
//! ## Loading Dependencies With [`Linker`]
//!
//! Use [`Linker::run`] and [`LinkerRun::load`] when you want a reusable [`LinkContext`]
//! and resolver-driven `DT_NEEDED` dependency loading. The built-in
//! [`linker::SearchPathResolver`] covers the common filesystem search-path case;
//! implement [`linker::KeyResolver`] when dependencies come from memory,
//! package stores, or another registry.
//!
//! ```rust,no_run
//! use elf_loader::{
//!     LinkContext, Linker, Result,
//!     input::PathBuf,
//!     linker::SearchPathResolver,
//! };
//!
//! fn main() -> Result<()> {
//!     let root = PathBuf::from("path/to/plugin.so");
//!     let mut context = LinkContext::for_process();
//!     let mut resolver = SearchPathResolver::new();
//!     resolver.push_rpath();
//!     resolver.push_runpath();
//!
//!     let loaded = Linker::new()
//!         .with_resolver(resolver)
//!         .run()
//!         .load(&mut context, root)?;
//!
//!     let run = unsafe {
//!         context
//!             .module(loaded.root())?
//!             .get::<extern "C" fn() -> i32>("run")?
//!             .expect("symbol `run` not found")
//!     };
//!     let _ = run();
//!     drop(loaded.release(&mut context)?);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Observer Hooks
//!
//! Observers are attached to a single loader or linker run, so reusable
//! [`Loader`] and [`Linker`] configuration can stay immutable while each run
//! decides which events to inspect or override.
//!
//! ```rust,no_run
//! use elf_loader::{
//!     Loader, Result,
//!     arch::NativeArch,
//!     observer::{BeforeLoadEvent, LoadObserver},
//!     relocation::RelocationArch,
//!     AddressSpaceId, Domain,
//! };
//!
//! struct TraceLoads;
//!
//! impl LoadObserver for TraceLoads {
//!     fn on_before_load(
//!         &mut self,
//!         event: BeforeLoadEvent<'_, (), <NativeArch as RelocationArch>::Layout>,
//!     ) -> Result<()> {
//!         let _path = event.path();
//!         let _is_dynamic = event.is_dynamic();
//!         Ok(())
//!     }
//! }
//!
//! fn main() -> Result<()> {
//!     let _raw = Loader::new()
//!         .run(Domain::native(AddressSpaceId::PROCESS))
//!         .with_observer(TraceLoads)
//!         .load_dylib("path/to/lib.so")?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! The default `full` feature enables `std`, `object`, and `lazy-binding`.
//! Disable default features for `no_std` builds. `use-syscall` and `std` are
//! mutually exclusive.
//!
//! - TLS relocation handling is always available. Pass a [`Domain`] to
//!   [`Loader::run`] or [`LinkContext::new`]. Domains start with TLS disabled;
//!   use [`Domain::with_tls`] to enable it.
//! - `lazy-binding`: enables the built-in `NativeLazyBinder`. Custom
//!   [`lazy::LazyBinder`] implementations and [`RelocatorRun::lazy`] are always available;
//!   [`Relocator::new`] remains eager until a binder is configured.
//! - `object`: enables `LoaderRun::load_object` and relocatable object (`ET_REL`) loading.
//! - `version`: enables version-aware `get_version` symbol lookups.
//! - `std`: enables standard-library integration and host-library imports on Linux/glibc.
//! - `log`, `portable-atomic`, and `use-syscall`: optional integrations for diagnostics and
//!   specialized targets.
//!
//! ## Platforms and Examples
//!
//! - The [`examples`](https://github.com/weizhiao/Relink/tree/main/examples) directory
//!   covers loading from memory, `LinkerRun::load`, scan-first linking, observer hooks,
//!   and object loading.
//! - The crate currently targets `x86_64`, `x86`, `aarch64`, `arm`, `riscv64`, `riscv32`,
//!   and `loongarch64`.
//! - Little-endian Xtensa ELF32 images have basic cross-architecture dynamic
//!   relocation support; lazy binding, native runtime hooks, and TLS relocation
//!   support are pending.
//! - Relocatable object support is currently centered on `x86_64` and `riscv64`.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_docs,
    unreachable_pub,
    clippy::unnecessary_wraps,
    clippy::unnecessary_lazy_evaluations,
    clippy::collapsible_if,
    clippy::cast_lossless,
    clippy::explicit_iter_loop,
    clippy::manual_assert,
    clippy::needless_question_mark,
    clippy::needless_return,
    clippy::needless_update,
    clippy::redundant_clone,
    clippy::redundant_else,
    clippy::redundant_static_lifetimes
)]
#![allow(
    clippy::len_without_is_empty,
    clippy::unnecessary_cast,
    clippy::uninit_vec
)]
extern crate alloc;

#[cfg(all(feature = "use-syscall", feature = "std"))]
compile_error!(
    "use-syscall cannot be combined with std; disable default features for a syscall build"
);

/// Compile-time check for supported architectures
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "riscv32",
    target_arch = "loongarch64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "xtensa",
)))]
compile_error!(
    "Unsupported target architecture. Supported architectures: x86_64, aarch64, riscv64, riscv32, loongarch64, x86, arm, xtensa"
);

mod aligned_bytes;
pub mod arch;
mod const_builder;
pub mod elf;
mod entity;
pub mod error;
mod hint;
#[cfg(all(feature = "std", target_os = "linux", target_env = "gnu"))]
pub mod host;
pub mod image;
pub mod input;
pub mod lazy;
pub mod linker;
pub mod loader;
mod logging;
pub mod memory;
#[cfg(feature = "object")]
pub mod object;
pub mod observer;
pub mod os;
pub mod relocation;
pub mod runtime;
mod segment;
mod sync;
pub mod tls;

pub(crate) use aligned_bytes::{AlignedBytes, try_cast_bytes};
pub(crate) use error::*;

pub use aligned_bytes::ByteRepr;
pub use error::Error;
pub use image::{
    ElfModule, GlobalScope, LocalScope, Module, ModuleInstanceId, ModuleScope, ModuleSearch,
    ModuleState, SearchPathPool,
};
pub use input::ModuleSourceId;
pub use linker::{GraphModule, LinkContext, Linker, LinkerRun, ModuleKey};
pub use loader::{Loader, LoaderRun};
pub use relocation::{Relocator, RelocatorRun};
pub use runtime::{AddressSpaceId, Domain, DomainId};

/// Result returned by loader and linker operations.
pub type Result<T> = core::result::Result<T, Error>;
