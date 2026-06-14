use crate::{
    Result,
    memory::{RegionAccess, VmAddr, VmOffset},
    os::{MapFlags, ProtFlags},
    segment::ElfSegments,
};
use alloc::vec::Vec;

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

/// A page-aligned memory protection change applied after mapping.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MemoryProtection {
    /// Runtime address of the protected range.
    addr: VmAddr,
    /// Unrounded protected range length.
    len: usize,
    /// Page size used to round the protected range.
    page_size: usize,
    /// Protection flags to apply.
    prot: ProtFlags,
}

impl MemoryProtection {
    #[inline]
    pub(crate) const fn new(addr: VmAddr, len: usize, page_size: usize, prot: ProtFlags) -> Self {
        Self {
            addr,
            len,
            page_size,
            prot,
        }
    }

    #[inline]
    pub(crate) fn apply<R: RegionAccess>(&self, segments: &ElfSegments<R>) -> Result<()> {
        let start = self.addr.rounddown(self.page_size);
        let end = (self.addr + VmOffset::new(self.len)).roundup(self.page_size);
        let len = end
            .checked_offset_from(start)
            .expect("protection range end precedes its start")
            .get();
        segments.mprotect(start, len, self.prot)
    }
}

/// An ELF segment in memory
///
/// This structure represents a loaded ELF segment with all the
/// information needed to manage its memory mapping, protection,
/// and data content.
pub(crate) struct ElfSegment {
    /// Module-relative offset of the segment.
    pub(crate) offset: VmOffset,
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
