//! # Relink (elf_loader)
//!
//! **Relink** is a high-performance runtime linker (JIT Linker) tailor-made for the Rust ecosystem.
//! It efficiently parses Various ELF formats, supporting loading from both traditional file systems
//! and direct memory images, and performs flexible dynamic and static hybrid linking.
//!
//! Whether you are developing **OS kernels**, **embedded systems**, **JIT compilers**, or building
//! **plugin-based applications**, Relink provides a solid foundation with zero-cost abstractions,
//! high-speed execution, and powerful extensibility.
//!
//! ## Core Features
//!
//! * **🛡️ Memory Safety**: Leverages Rust's ownership and `Arc` to manage library lifetimes and dependencies automatically.
//! * **🔀 Hybrid Linking**: Seamlessly mix Relocatable Object files (`.o`) and Dynamic Shared Objects (`.so`).
//! * **🎭 Customization**: Deeply intervene in symbol resolution and relocation through `SymbolLookup` and `RelocationHandler`.
//! * **⚡ Performance & Versatility**: Optimized for `no_std` environments with support for RELR and Lazy Binding.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use elf_loader::{Loader, input::ElfBinary};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Load the library and perform instant linking
//!     let lib = Loader::new().load_dylib(ElfBinary::new("my_lib", &[]))?
//!         .relocator()
//!         .relocate()?; // Complete all relocations
//!
//!     // 2. Safely retrieve and call the function
//!     let awesome_func = unsafe {
//!         lib.get::<fn(i32) -> i32>("awesome_func").ok_or("symbol not found")?
//!     };
//!     let result = awesome_func(42);
//!     
//!     Ok(())
//! }
//! ```
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

pub mod arch;
pub mod elf;
mod error;
pub mod image;
pub mod input;
pub mod loader;
pub mod os;
pub mod relocation;
mod segment;
mod sync;
pub mod tls;

pub(crate) use error::*;

pub use error::Error;
pub use loader::Loader;

/// A type alias for `Result`s returned by `elf_loader` functions.
///
/// This is a convenience alias that eliminates the need to repeatedly specify
/// the `Error` type in function signatures.
pub type Result<T> = core::result::Result<T, Error>;
