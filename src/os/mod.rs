//! Operating system and environment abstractions.
//!
//! This module provides traits for low-level memory operations such as
//! memory mapping (`mmap`) and memory protection (`mprotect`). It allows
//! the ELF loader to be portable across different operating systems
//! and bare-metal environments.

use bitflags::bitflags;
use core::ffi::c_int;

pub use traits::Mmap;

mod traits;

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    /// Memory protection flags for controlling access permissions.
    ///
    /// These flags determine what operations can be performed on a mapped memory region.
    /// They can be combined using bitwise OR operations.
    pub struct ProtFlags: c_int {
        /// No access allowed. Useful for reserving address space.
        const PROT_NONE = 0;

        /// Allow reading from the memory region.
        const PROT_READ = 1;

        /// Allow writing to the memory region.
        const PROT_WRITE = 2;

        /// Allow executing code in the memory region.
        const PROT_EXEC = 4;
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    /// Memory mapping configuration flags.
    ///
    /// These flags control how memory mappings are created and behave.
    /// They specify sharing behavior, address placement, and mapping type.
    pub struct MapFlags: c_int {
        /// Create a private copy-on-write mapping. Changes are not visible to other processes.
        const MAP_PRIVATE = 2;

        /// Place the mapping at exactly the specified address. Fails if the address is already in use.
        const MAP_FIXED = 16;

        /// Create an anonymous mapping not backed by any file. Used for allocating memory.
        const MAP_ANONYMOUS = 32;
    }
}

cfg_if::cfg_if! {
    if #[cfg(windows)]{
        mod windows;
        pub(crate) use windows::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use windows::DefaultMmap;
    }else if #[cfg(feature = "use-syscall")]{
        mod linux_syscall;
        pub(crate) use linux_syscall::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use linux_syscall::*;
    }else if #[cfg(unix)]{
        mod unix;
        pub(crate) use unix::{current_thread_id, register_thread_destructor, get_thread_local_ptr, RawFile};
        pub use unix::DefaultMmap;
    }else {
        mod baremetal;
        pub(crate) use baremetal::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use baremetal::*;
    }
}
