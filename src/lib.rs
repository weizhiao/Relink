//! # Relink
//!
//! Relink is a high-performance, `no_std`-friendly ELF loader and runtime linker for Rust.
//! It maps ELF images from files or memory, performs relocations at runtime, and exposes
//! typed symbol lookups with Rust lifetimes.
//!
//! ## Start with [`Loader`]
//!
//! - Use [`Loader::load`] to auto-detect whether the input is a dylib, executable, or
//!   relocatable object.
//! - Use [`Loader::scan`] to classify executable or dynamic ELF metadata without mapping it.
//! - Use [`Loader::load_dylib`] or [`Loader::load_exec`] when you want strict type checks.
//! - Use [`Loader::load_dynamic`] when you want any `PT_DYNAMIC` image, including a dynamic
//!   `ET_EXEC`.
//! - Use [`Loader::scan`] and [`Loader::load_scanned_dynamic`] to split dynamic metadata
//!   discovery from mapping.
//! - Use `Loader::load_object` to load `ET_REL` object files when the `object` feature is enabled.
//! - Inputs can come from file paths, [`input::Path`] / [`input::PathBuf`], raw bytes,
//!   [`input::ElfFile`], or [`input::ElfBinary`].
//!
//! ## Highlights
//!
//! - Safer symbol lifetimes. Typed symbols borrow the loaded image, so they cannot outlive
//!   the library that produced them.
//! - Hybrid linking. Compose `.so`, `.o`, and synthetic modules at runtime with `scope()` and
//!   `extend_scope()`.
//! - Explicit dependency loading. Build your own dependency policy with an
//!   actual [`Loader`], [`linker::KeyResolver`], [`Linker`], and [`LinkContext`].
//! - Deep customization. Inject host or bridge symbols with
//!   [`image::SyntheticModule`] and intercept relocations with handlers.
//! - Optional advanced features. Lazy binding, relocatable object loading, logging, and
//!   versioned symbol lookup are feature-gated; TLS supports both the built-in and custom resolvers.
//!
//! ## Example
//!
//! ```rust,no_run
//! use elf_loader::{
//!     Loader, Relocator, Result,
//!     image::{SyntheticSymbol, SyntheticModule},
//! };
//!
//! extern "C" fn host_double(value: i32) -> i32 {
//!     value * 2
//! }
//!
//! fn main() -> Result<()> {
//!     let host = SyntheticModule::new(
//!         "__host",
//!         [SyntheticSymbol::function("host_double", host_double as *const ())],
//!     );
//!
//!     let lib = Relocator::new()
//!         .run(Loader::new().load_dylib("path/to/plugin.so")?)
//!         .scope([host])
//!         .relocate()?;
//!
//!     let run = unsafe {
//!         lib.get::<extern "C" fn(i32) -> i32>("run")
//!             .expect("symbol `run` not found")
//!     };
//!     assert_eq!(run(21), 42);
//!     Ok(())
//! }
//! ```
//!
//! ## Loading Dependencies With [`Linker`]
//!
//! Use [`Linker::load`] when you want a reusable [`LinkContext`]
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
//!     runtime::DomainId,
//! };
//!
//! fn main() -> Result<()> {
//!     let root = PathBuf::from("path/to/plugin.so");
//!     let mut context = LinkContext::<()>::new(DomainId::PROCESS);
//!     let mut resolver = SearchPathResolver::new();
//!     resolver.push_rpath();
//!     resolver.push_runpath();
//!
//!     let loaded = Linker::new()
//!         .resolver(resolver)
//!         .load(&mut context, root)?;
//!
//!     let run = unsafe {
//!         context
//!             .module(loaded.root())?
//!             .get::<extern "C" fn() -> i32>("run")
//!             .expect("symbol `run` not found")
//!     };
//!     let _ = run();
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
//!         .run()
//!         .with_observer(TraceLoads)
//!         .load_dylib("path/to/lib.so")?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - TLS relocation handling is always available. For TLS-using modules, start from
//!   `Loader::with_default_tls_resolver` or provide a custom TLS resolver.
//! - `lazy-binding`: enables `Relocator::lazy` and PLT/GOT lazy binding.
//! - `object`: enables `Loader::load_object` and relocatable object (`ET_REL`) loading.
//! - `version`: enables version-aware symbol lookup via `ModuleHandle::get_version`.
//! - `log`, `portable-atomic`, and `use-syscall`: optional integrations for diagnostics and
//!   specialized targets.
//!
//! ## More
//!
//! - The [`examples`](https://github.com/weizhiao/Relink/tree/main/examples) directory
//!   covers loading from memory, `Linker::load`, scan-first linking, observer hooks,
//!   and object loading.
//! - The crate currently targets `x86_64`, `x86`, `aarch64`, `arm`, `riscv64`, `riscv32`,
//!   and `loongarch64`.
//! - Little-endian Xtensa ELF32 images have basic cross-architecture dynamic
//!   relocation and custom-binder lazy binding support; native runtime hooks and
//!   full TLS support are pending.
//! - Relocatable object support is currently centered on `x86_64` and `riscv64`.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![warn(
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
pub use image::{Module, ModuleInstanceId, ModuleSearch, ModuleState, SearchPathPool};
pub use input::ModuleSourceId;
pub use linker::{LinkContext, Linker, LinkerRun, ModuleKey};
pub use loader::{Loader, LoaderRun};
pub use relocation::{Relocator, RelocatorRun};

/// A type alias for `Result`s returned by `elf_loader` functions.
///
/// This is a convenience alias that eliminates the need to repeatedly specify
/// the `Error` type in function signatures.
pub type Result<T> = core::result::Result<T, Error>;
