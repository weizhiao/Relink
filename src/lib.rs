//! # Relink (elf_loader)
//!
//! **Relink** is a high-performance runtime linker (JIT Linker) tailor-made for the Rust ecosystem. It efficiently parses various ELF formats—not only from traditional file systems but also directly from memory images—and performs flexible dynamic and static hybrid linking.
//!
//! Whether you are developing **OS kernels**, **embedded systems**, **JIT compilers**, or building **plugin-based applications**, Relink provides a solid foundation with zero-cost abstractions, high-speed execution, and powerful extensibility.
//!
//! ## 🔥 Key Features
//!
//! ### 🛡️ Memory Safety
//! Leveraging Rust's ownership system and smart pointers, Relink ensures safety at runtime.
//! * **Lifetime Binding**: Symbols retrieved from a library carry lifetime markers. The compiler ensures they do not outlive the library itself, erasing `use-after-free` risks.
//! * **Automatic Dependency Management**: Uses `Arc` to automatically maintain dependency trees between libraries, preventing a required library from being dropped prematurely.
//!
//! ### 🔀 Hybrid Linking Capability
//! Relink supports mixing **Relocatable Object files (`.o`)** and **Dynamic Shared Objects (`.so`)**. You can load a `.o` file just like a dynamic library and link its undefined symbols to the system or other loaded libraries at runtime.
//!
//! ### 🎭 Deep Customization & Interception
//! By implementing the `SymbolLookup` and `RelocationHandler` traits, users can deeply intervene in the linking process.
//! * **Symbol Interception**: Intercept and replace external dependency symbols during loading. Perfect for function mocking, behavioral monitoring, or hot-patching.
//! * **Custom Linking Logic**: Take full control over symbol resolution strategies to build highly flexible plugin systems.
//!
//! ### ⚡ Extreme Performance & Versatility
//! * **Zero-Cost Abstractions**: Built with Rust to provide near-native loading and symbol resolution speeds.
//! * **`no_std` Support**: The core library has no OS dependencies, making it ideal for **OS kernels**, **embedded devices**, and **bare-metal development**.
//! * **Modern Features**: Supports **RELR** for modern ELF optimization; supports **Lazy Binding** to improve cold-start times for large dynamic libraries.
//!
//! ## 🚀 Quick Start
//!
//! ```rust,no_run
//! use elf_loader::Loader;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Load the library and perform instant linking
//!     let lib = Loader::new().load_dylib("path/to/your_library.so")?
//!         .relocator()
//!         // Optional: Provide custom symbol resolution (e.g., export symbols from host)
//!         .pre_find_fn(|sym_name| {
//!             if sym_name == "my_host_function" {
//!                 Some(my_host_function as *const ())
//!             } else {
//!                 None
//!             }
//!         })
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
//!
//! // A host function that can be called by the plugin
//! extern "C" fn my_host_function(value: i32) -> i32 {
//!     value * 2
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
