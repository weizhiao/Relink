use crate::os::{MapFlags, ProtFlags, VmOffset};
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
