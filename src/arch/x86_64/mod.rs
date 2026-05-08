//! x86-64 architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86-64 specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

// `lazy` and `tls` use naked assembly tied to this module's architecture, so
// gate them on `target_arch`. `object` is a pure-data helper and stays
// platform-independent. The retained-relocation `GotPltTarget` impl that used
// to live in `rewrite.rs` was folded into `relocation.rs` alongside the
// other architecture-specific trait impls.
#[cfg(all(feature = "lazy-binding", target_arch = "x86_64"))]
mod lazy;
#[cfg(feature = "object")]
pub(crate) mod object;
#[cfg(all(feature = "tls", target_arch = "x86_64"))]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "x86_64"))]
pub(crate) use lazy::{DYLIB_OFFSET, RESOLVE_FUNCTION_OFFSET, dl_runtime_resolve};
#[cfg(all(feature = "tls", target_arch = "x86_64"))]
pub(crate) use tls::{get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static};

pub mod relocation;
