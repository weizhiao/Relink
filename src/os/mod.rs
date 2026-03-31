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

/// Behaviors for the madvise() Linux system call.
///
/// See https://man7.org/linux/man-pages/man2/madvise.2.html for documentation
///
/// Defined in Linux at https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/asm-generic/mman-common.h.
///
/// TODO some of these values are incorrect for alpha, mips, parisc, and xtensa arches.
#[repr(C)]
pub enum MadviseAdvice {
    Normal = 0,
    Random = 1,
    Sequential = 2,
    WillNeed = 3,
    DontNeed = 4,
    Free = 8,
    Remove = 9,
    DontFork = 10,
    DoFork = 11,
    HWPoison = 100,
    SoftOffline = 101,
    Mergeable = 12,
    Unmergeable = 13,
    HugePage = 14,
    NoHugePage = 15,
    // Introduced in Linux 3.4.
    DontDump = 16,
    // Introduced in Linux 3.4.
    DoDump = 17,
    // Introduced in Linux 4.14.
    WipeOnFork = 18,
    // Introduced in Linux 4.14.
    KeepOnFork = 19,
    // Introduced in Linux 5.4.
    Cold = 20,
    // Introduced in Linux 5.4.
    PageOut = 21,
    // Introduced in Linux 5.14.
    PopulateRead = 22,
    // Introduced in Linux 5.14.
    PopulateWrite = 23,
    // Introduced in Linux 5.18.
    DontNeedLocked = 24,
    // Introduced in Linux 6.1.
    Collapse = 25,
    // Introduced in Linux 6.13.
    GuardInstall = 102,
    // Introduced in Linux 6.13.
    GuardRemove = 103,
}

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
    }else if #[cfg(unix)]{
        mod unix;
        #[cfg(feature = "tls")]
        pub(crate) use unix::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use unix::RawFile;
        pub use unix::DefaultMmap;
    }else {
        mod baremetal;
        #[cfg(feature = "tls")]
        pub(crate) use baremetal::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use baremetal::RawFile;
        pub use baremetal::*;
    }
}
