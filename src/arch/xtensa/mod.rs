//! Xtensa ELF relocation support.

#[cfg(target_arch = "xtensa")]
mod tls;

#[cfg(target_arch = "xtensa")]
pub(crate) use tls::{
    get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static,
    tlsdesc_resolver_undefweak,
};

pub(crate) mod relocation;
pub use relocation::XtensaArch;
