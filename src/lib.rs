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
//! - Inputs can come from file paths, raw bytes, [`input::ElfFile`], or [`input::ElfBinary`].
//!
//! ## Highlights
//!
//! - Safer symbol lifetimes. Typed symbols borrow the loaded image, so they cannot outlive
//!   the library that produced them.
//! - Hybrid linking. Compose `.so` and `.o` inputs at runtime with `scope()` and
//!   `add_scope()`.
//! - Explicit dependency loading. Build your own dependency policy with an
//!   actual [`Loader`], [`linker::KeyResolver`], [`linker::Linker`], and
//!   [`linker::LinkContext`].
//! - Deep customization. Override relocation-time lookup with `pre_find_fn()` /
//!   `post_find_fn()`, provide lazy-fixup lookup with `lazy_pre_find_fn()` /
//!   `lazy_post_find_fn()`, intercept relocations with handlers, and inspect segments
//!   with [`loader::LoadHook`].
//! - Optional advanced features. TLS relocation handling, lazy binding, relocatable object
//!   loading, logging, and versioned symbol lookup are feature-gated.
//!
//! ## Example
//!
//! ```rust,no_run
//! use elf_loader::{Loader, Result};
//!
//! extern "C" fn host_double(value: i32) -> i32 {
//!     value * 2
//! }
//!
//! fn main() -> Result<()> {
//!     let lib = Loader::new()
//!         .load_dylib("path/to/plugin.so")?
//!         .relocator()
//!         .pre_find_fn(|name| {
//!             if name == "host_double" {
//!                 Some(host_double as *const ())
//!             } else {
//!                 None
//!             }
//!         })
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
//! ## Feature Flags
//!
//! - `tls` (default): enables TLS relocation handling. For TLS-using modules, start from
//!   [`Loader::with_default_tls_resolver`] or provide a custom TLS resolver.
//! - `lazy-binding`: enables `Relocator::lazy` and PLT/GOT lazy binding.
//! - `object`: enables `Loader::load_object` and relocatable object (`ET_REL`) loading.
//! - `version`: enables version-aware symbol lookup via `ElfCore::get_version`.
//! - `log`, `portable-atomic`, and `use-syscall`: optional integrations for diagnostics and
//!   specialized targets.
//!
//! ## More
//!
//! - The [`examples`](https://github.com/weizhiao/elf_loader/tree/main/examples) directory
//!   covers loading from memory, lifecycle hooks, relocation handlers, and object loading.
//! - The crate currently targets `x86_64`, `x86`, `aarch64`, `arm`, `riscv64`, `riscv32`,
//!   and `loongarch64`.
//! - Relocatable object support is currently centered on `x86_64`.
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![no_std]
#![warn(
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
)))]
compile_error!(
    "Unsupported target architecture. Supported architectures: x86_64, aarch64, riscv64, riscv32, loongarch64, x86, arm"
);

mod aligned_bytes;
pub mod arch;
pub mod elf;
mod entity;
mod error;
pub mod image;
pub mod input;
pub mod linker;
pub mod loader;
mod logging;
#[cfg(feature = "object")]
mod object;
pub mod os;
pub mod relocation;
mod segment;
mod sync;
pub mod tls;

pub(crate) use aligned_bytes::ByteRepr;
pub(crate) use error::*;

pub use aligned_bytes::AlignedBytes;
pub use error::{
    CustomError, Error, IoError, LinkerError, MmapError, ParseDynamicError, ParseEhdrError,
    ParsePhdrError, RelocationContextError, RelocationError, TlsError,
};
pub use loader::Loader;

/// A type alias for `Result`s returned by `elf_loader` functions.
///
/// This is a convenience alias that eliminates the need to repeatedly specify
/// the `Error` type in function signatures.
pub type Result<T> = core::result::Result<T, Error>;
