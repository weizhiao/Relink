//! AArch64 ELF relocation, TLS, and lazy PLT binding.

// `lazy` and `tls` contain naked assembly that is only valid when the host
// CPU matches this module's architecture. Other architectures only need the
// pure-data items (relocation type numbers, ...) so we gate the
// platform-specific submodules on `target_arch`.
#[cfg(all(feature = "lazy-binding", target_arch = "aarch64"))]
mod lazy;
#[cfg(target_arch = "aarch64")]
mod tls;

#[cfg(all(feature = "lazy-binding", target_arch = "aarch64"))]
pub(crate) use lazy::dl_runtime_resolve;
#[cfg(target_arch = "aarch64")]
pub(crate) use tls::{
    get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static,
    tlsdesc_resolver_undefweak,
};

pub(crate) mod relocation;
pub use relocation::AArch64Arch;
