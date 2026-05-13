//! Operating system and environment abstractions.
//!
//! This module provides traits for low-level memory operations such as
//! memory mapping (`mmap`) and memory protection (`mprotect`). It allows
//! the ELF loader to be portable across different operating systems
//! and bare-metal environments.

pub use defs::{MadviseAdvice, MapFlags, PageSize, ProtFlags};
pub use traits::Mmap;

mod defs;
mod traits;

cfg_if::cfg_if! {
    if #[cfg(windows)]{
        mod windows;
        #[cfg(feature = "tls")]
        pub(crate) use windows::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use windows::{RawFile, virtual_free};
        pub use windows::DefaultMmap;
    }else if #[cfg(feature = "use-syscall")]{
        mod linux_syscall;
        #[cfg(feature = "tls")]
        pub(crate) use linux_syscall::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use linux_syscall::RawFile;
        pub use linux_syscall::*;
    }else if #[cfg(all(any(target_os = "linux", target_os = "android"), feature = "libc"))]{
        mod linux_libc;
        #[cfg(feature = "tls")]
        pub(crate) use linux_libc::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use linux_libc::RawFile;
        pub use linux_libc::DefaultMmap;
    }else {
        mod baremetal;
        #[cfg(feature = "tls")]
        pub(crate) use baremetal::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use baremetal::RawFile;
        pub use baremetal::*;
    }
}
