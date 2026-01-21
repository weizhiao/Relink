//! Memory mapping operations for ELF loader
//!
//! This module provides traits and implementations for memory mapping operations
//! required by the ELF loader. It abstracts platform-specific memory management
//! to offer a unified interface for mapping, unmapping, and protecting memory regions.
//!
//! Key concepts:
//! - **Memory Mapping**: Allows files or data to be mapped directly into memory.
//! - **Protection Flags**: Control read, write, and execute permissions.
//! - **Mapping Flags**: Specify how the mapping behaves (e.g., private, fixed address).
//!
//! # Safety
//! Memory mapping involves direct manipulation of the process's address space.
//! Incorrect usage can cause crashes, data corruption, or security issues.
//! Always ensure proper bounds checking and permission handling.

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
        pub(crate) mod windows;
        pub(crate) use windows::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use windows::*;
    }else if #[cfg(feature = "use-syscall")]{
        pub(crate) mod linux_syscall;
        pub(crate) use linux_syscall::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use linux_syscall::*;
    }else if #[cfg(unix)]{
        pub(crate) mod unix;
        pub(crate) use unix::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use unix::*;
    }else {
        pub(crate) mod baremetal;
        pub(crate) use baremetal::{current_thread_id, register_thread_destructor, get_thread_local_ptr};
        pub use baremetal::*;
    }
}
