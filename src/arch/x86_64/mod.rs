//! x86-64 architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86-64 specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

#[cfg(all(feature = "lazy-binding", target_arch = "x86_64"))]
mod lazy;
#[cfg(feature = "object")]
pub(crate) mod object;
mod plt;
#[cfg(target_arch = "x86_64")]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "x86_64"))]
pub(crate) use lazy::dl_runtime_resolve;
#[cfg(target_arch = "x86_64")]
pub(crate) use tls::{
    get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static,
    tlsdesc_resolver_undefweak,
};

pub(crate) mod relocation;
pub use relocation::X86_64Arch;
