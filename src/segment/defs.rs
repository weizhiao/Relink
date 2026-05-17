use crate::{
    logging,
    os::{MapFlags, Mapper, ProtFlags},
    sync::Arc,
};
use alloc::vec::Vec;
use core::ffi::c_void;

/// Address representation for ELF segments
///
/// This enum represents either a relative address (offset from base)
/// or an absolute address (fully resolved virtual address).
pub(crate) enum Address {
    /// Relative address (offset from base address)
    Relative(usize),

    /// Absolute address (fully resolved virtual address)
    Absolute(usize),
}

impl Address {
    /// Get the absolute address
    ///
    /// # Returns
    /// The absolute address value
    ///
    /// # Panics
    /// Panics if called on a Relative address variant
    pub(super) fn absolute_addr(&self) -> usize {
        match self {
            Address::Relative(_) => unreachable!(),
            Address::Absolute(addr) => *addr,
        }
    }

    /// Get the relative address
    ///
    /// # Returns
    /// The relative address value
    ///
    /// # Panics
    /// Panics if called on an Absolute address variant
    pub(super) fn relative_addr(&self) -> usize {
        match self {
            Address::Relative(addr) => *addr,
            Address::Absolute(_) => unreachable!(),
        }
    }
}

/// Information about a file mapping within a segment
///
/// This structure describes how a portion of a file is mapped
/// into a memory segment.
#[derive(Debug)]
pub(crate) struct FileMapInfo {
    /// Start offset within the segment
    pub(crate) start: usize,
    /// Size of the file data in bytes
    pub(crate) filesz: usize,
    /// Offset within the file
    pub(crate) offset: usize,
}

/// An ELF segment in memory
///
/// This structure represents a loaded ELF segment with all the
/// information needed to manage its memory mapping, protection,
/// and data content.
pub(crate) struct ElfSegment {
    /// Address of the segment in memory
    pub(crate) addr: Address,
    /// Memory protection flags for the segment
    pub(crate) prot: ProtFlags,
    /// Memory mapping flags for the segment
    pub(crate) flags: MapFlags,
    /// Total length of the segment in bytes
    pub(crate) len: usize,
    /// Page size used to align this segment.
    pub(crate) page_size: usize,
    /// Size of zero-filled area at the end of the segment
    pub(crate) zero_size: usize,
    /// Size of content (non-zero) area in the segment
    pub(crate) content_size: usize,
    /// Information about file mappings within this segment
    pub(crate) map_info: Vec<FileMapInfo>,
    /// Indicates if data needs to be copied manually
    pub(crate) need_copy: bool,
    /// Indicates if this segment comes from a relocatable object
    pub(crate) from_relocatable: bool,
}

pub(crate) struct MappedRegion {
    pub(super) memory: *mut c_void,
    pub(super) len: usize,
    mapper: Mapper,
}

impl MappedRegion {
    #[inline]
    pub(super) fn new(memory: *mut c_void, len: usize, mapper: Mapper) -> Self {
        Self {
            memory,
            len,
            mapper,
        }
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        let res = unsafe { self.mapper.munmap(self.memory, self.len) };
        debug_assert!(res.is_ok(), "failed to unmap ELF segments");
        if let Err(err) = res {
            logging::error!("failed to unmap ELF segments: {err}");
        }
    }
}

// Safety: the region only owns an mmap-style allocation and unmaps it on drop.
unsafe impl Send for MappedRegion {}
// Safety: the region does not expose interior mutability beyond the mapped bytes themselves.
unsafe impl Sync for MappedRegion {}

#[derive(Clone)]
pub(crate) struct MappedSlice {
    pub(super) offset: usize,
    pub(super) len: usize,
    // This shared owner keeps the mapped arena alive even when address math
    // only needs the slice bounds at runtime.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(super) region: Arc<MappedRegion>,
}

impl MappedSlice {
    #[inline]
    pub(super) fn new(offset: usize, len: usize, region: Arc<MappedRegion>) -> Self {
        Self {
            offset,
            len,
            region,
        }
    }

    #[inline]
    pub(super) fn contains_range(&self, start: usize, len: usize) -> bool {
        start
            .checked_sub(self.offset)
            .and_then(|delta| delta.checked_add(len))
            .is_some_and(|end| end <= self.len)
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(super) fn offset(&self) -> usize {
        self.offset
    }
}
