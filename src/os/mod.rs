//! Operating system and environment abstractions.
//!
//! This module provides traits for low-level memory operations such as
//! memory mapping (`mmap`) and memory protection (`mprotect`). It allows
//! the ELF loader to be portable across different operating systems
//! and bare-metal environments.

use bitflags::bitflags;
use core::{ffi::c_int, num::NonZeroUsize};

pub use traits::Mmap;

mod traits;

/// Page size used by memory mapping operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PageSize {
    /// Regular 4 KiB base pages.
    #[default]
    Base,
    /// 2 MiB huge pages.
    Huge2MiB,
    /// 1 GiB huge pages.
    Huge1GiB,
    /// A caller-provided power-of-two page size.
    Custom(NonZeroUsize),
}

impl PageSize {
    /// Regular base-page size in bytes.
    pub const BASE_BYTES: usize = 4 * 1024;
    /// 2 MiB huge-page size in bytes.
    pub const HUGE_2MIB_BYTES: usize = 2 * 1024 * 1024;
    /// 1 GiB huge-page size in bytes.
    pub const HUGE_1GIB_BYTES: usize = 1024 * 1024 * 1024;

    /// Creates a page-size descriptor from a non-zero power-of-two byte size.
    #[inline]
    pub const fn new(bytes: usize) -> Option<Self> {
        if !bytes.is_power_of_two() {
            return None;
        }

        match bytes {
            Self::BASE_BYTES => Some(Self::Base),
            Self::HUGE_2MIB_BYTES => Some(Self::Huge2MiB),
            Self::HUGE_1GIB_BYTES => Some(Self::Huge1GiB),
            _ => match NonZeroUsize::new(bytes) {
                Some(bytes) => Some(Self::Custom(bytes)),
                None => None,
            },
        }
    }

    /// Returns the page size in bytes.
    #[inline]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Base => Self::BASE_BYTES,
            Self::Huge2MiB => Self::HUGE_2MIB_BYTES,
            Self::Huge1GiB => Self::HUGE_1GIB_BYTES,
            Self::Custom(bytes) => bytes.get(),
        }
    }

    /// Returns whether this page size is one of the built-in huge-page sizes.
    #[inline]
    pub const fn is_huge(self) -> bool {
        matches!(self, Self::Huge2MiB | Self::Huge1GiB)
    }
}

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

        /// Request a Linux hugetlb mapping.
        ///
        /// This is Linux-specific and requires an appropriately configured
        /// huge page pool. It is usually combined with `MAP_ANONYMOUS`.
        const MAP_HUGETLB = 0x40000;

        /// Request 2 MiB huge pages for a `MAP_HUGETLB` mapping.
        ///
        /// Linux encodes the base-2 page size logarithm in the mmap flags.
        const MAP_HUGE_2MB = 21 << 26;

        /// Request 1 GiB huge pages for a `MAP_HUGETLB` mapping.
        ///
        /// Linux encodes the base-2 page size logarithm in the mmap flags.
        const MAP_HUGE_1GB = 30 << 26;
    }
}

impl MapFlags {
    /// Returns Linux hugetlb flags for a huge page size.
    ///
    /// The returned flags include [`MapFlags::MAP_HUGETLB`]. Base pages return
    /// `None` because they do not need huge-page mmap flags. Custom page sizes
    /// also return `None` unless they match one of the built-in huge-page sizes.
    #[inline]
    pub const fn huge_page_size(page_size: PageSize) -> Option<Self> {
        match page_size {
            PageSize::Base => None,
            PageSize::Huge2MiB => Some(Self::MAP_HUGETLB.union(Self::MAP_HUGE_2MB)),
            PageSize::Huge1GiB => Some(Self::MAP_HUGETLB.union(Self::MAP_HUGE_1GB)),
            PageSize::Custom(_) => None,
        }
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
