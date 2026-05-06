use crate::input::ElfReader;
use crate::os::{MapFlags, Mmap, ProtFlags};
use crate::{Result, logging, segment::ElfSegments};
use alloc::vec::Vec;

use super::roundup;

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
    fn absolute_addr(&self) -> usize {
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
    fn relative_addr(&self) -> usize {
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

impl ElfSegment {
    #[inline]
    fn mapping_prot(&self) -> ProtFlags {
        if self.from_relocatable {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        } else {
            self.prot
        }
    }

    /// Rebase the segment with a new base address
    ///
    /// This method converts a relative address to an absolute address
    /// by adding the provided base address.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the relative address
    fn rebase(&mut self, base: usize) {
        self.addr = Address::Absolute(base + self.addr.relative_addr());
    }

    /// Map the segment into memory
    ///
    /// This method maps the segment into memory using the appropriate
    /// memory mapping operations based on the segment's properties.
    ///
    /// # Arguments
    /// * `object` - The ELF object to map data from
    ///
    /// # Returns
    /// * `Ok(())` - If mapping succeeds
    /// * `Err(Error)` - If mapping fails
    fn mmap_segment<M: Mmap>(&mut self, object: &mut impl ElfReader) -> Result<()> {
        let mut need_copy = false;
        let len = self.len;
        let addr = self.addr.absolute_addr();
        let prot = self.mapping_prot();

        debug_assert!(len.is_multiple_of(self.page_size));

        if self.map_info.len() == 1 {
            debug_assert!(self.map_info[0].offset.is_multiple_of(self.page_size));
            unsafe {
                M::mmap(
                    Some(addr),
                    len,
                    prot,
                    self.flags,
                    self.map_info[0].offset,
                    object.as_fd(),
                    &mut need_copy,
                )
            }?
        } else {
            unsafe { M::mmap(Some(addr), len, prot, self.flags, 0, None, &mut need_copy) }?
        };

        logging::trace!(
            "[Mmap] address: 0x{:x}, length: {}, flags: {:?}, zero_size: {}, map_info: {:?}",
            addr,
            len,
            prot,
            self.zero_size,
            self.map_info
        );

        self.need_copy = need_copy;
        Ok(())
    }

    /// Copy data into the mapped segment
    ///
    /// This method copies data from the ELF object into the mapped
    /// memory segment when manual copying is required.
    ///
    /// # Arguments
    /// * `object` - The ELF object to copy data from
    ///
    /// # Returns
    /// * `Ok(())` - If copying succeeds
    /// * `Err(Error)` - If copying fails
    fn copy_data(&self, object: &mut impl ElfReader) -> Result<()> {
        if self.need_copy {
            let ptr = self.addr.absolute_addr() as *mut u8;
            for info in &self.map_info {
                unsafe {
                    let dest = core::slice::from_raw_parts_mut(ptr.add(info.start), info.filesz);
                    object.read(dest, info.offset)?;
                }
            }
        }
        Ok(())
    }

    /// Change memory protection of the segment
    ///
    /// This method adjusts the memory protection of the segment
    /// after initial mapping, typically to make it executable
    /// or read-only as required.
    ///
    /// # Returns
    /// * `Ok(())` - If protection change succeeds
    /// * `Err(Error)` - If protection change fails
    fn mprotect<M: Mmap>(&self) -> Result<()> {
        if self.need_copy || self.from_relocatable {
            let len = self.len;
            debug_assert!(len.is_multiple_of(self.page_size));
            let addr = self.addr.absolute_addr();
            unsafe { M::mprotect(addr as _, len, self.prot) }?;

            logging::trace!(
                "[Mprotect] address: 0x{:x}, length: {}, prot: {:?}",
                addr,
                len,
                self.prot,
            );
        }
        Ok(())
    }

    /// Fill zero-initialized areas of the segment
    ///
    /// This method fills any zero-initialized areas of the segment
    /// with zeros, either by writing directly or by mapping
    /// anonymous pages.
    ///
    /// # Returns
    /// * `Ok(())` - If filling succeeds
    /// * `Err(Error)` - If filling fails
    fn fill_zero<M: Mmap>(&self) -> Result<()> {
        if self.zero_size > 0 {
            let zero_start = self.addr.absolute_addr() + self.content_size;
            let zero_end = roundup(zero_start, self.page_size);
            let write_len = zero_end - zero_start;
            let ptr = zero_start as *mut u8;
            unsafe {
                ptr.write_bytes(0, write_len);
            };

            if write_len < self.zero_size {
                let zero_mmap_addr = zero_end;
                let zero_mmap_len = self.zero_size - write_len;
                let prot = self.mapping_prot();

                unsafe {
                    M::mmap_anonymous(
                        zero_mmap_addr,
                        zero_mmap_len,
                        prot,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Trait for building ELF segments
///
/// This trait provides the interface for creating and managing
/// ELF segments during the loading process.
pub(crate) trait SegmentBuilder {
    /// Create the address space for the segments
    ///
    /// # Returns
    /// * `Ok(ElfSegments)` - The created segment space
    /// * `Err(Error)` - If creation fails
    fn create_space<M: Mmap>(&mut self) -> Result<ElfSegments>;

    /// Create the individual segments
    ///
    /// # Returns
    /// * `Ok(())` - If creation succeeds
    /// * `Err(Error)` - If creation fails
    fn create_segments(&mut self) -> Result<()>;

    /// Get mutable reference to segments
    ///
    /// # Returns
    /// Mutable reference to the segment array
    fn segments_mut(&mut self) -> &mut [ElfSegment];

    /// Get reference to segments
    ///
    /// # Returns
    /// Reference to the segment array
    fn segments(&self) -> &[ElfSegment];

    /// Load segments into memory
    ///
    /// This method orchestrates the loading of all segments
    /// into memory, including mapping, data copying, and
    /// zero-filling.
    ///
    /// # Arguments
    /// * `object` - The ELF object to load segments from
    ///
    /// # Returns
    /// * `Ok(ElfSegments)` - The loaded segments
    /// * `Err(Error)` - If loading fails
    fn load_segments<M: Mmap>(&mut self, object: &mut impl ElfReader) -> Result<ElfSegments> {
        let space = self.create_space::<M>()?;
        self.create_segments()?;
        let segments = self.segments_mut();
        let base = space.base();

        #[cfg(windows)]
        let mut last_addr = space
            .primary_backing()
            .map(|(memory, _)| memory as usize)
            .unwrap_or(base);

        for segment in segments.iter_mut() {
            segment.rebase(base);
            #[cfg(windows)]
            if object.as_fd().is_some() {
                let addr = segment.addr.absolute_addr();
                let len = segment.len;
                if addr > last_addr {
                    crate::os::virtual_free(last_addr, addr - last_addr)?;
                }
                let space_end = space
                    .primary_backing()
                    .map(|(memory, len)| memory as usize + len)
                    .unwrap_or(space.mapped_base() + space.mapped_len());
                if addr + len < space_end {
                    crate::os::virtual_free(addr + len, space_end - (addr + len))?;
                }
                last_addr = addr + len;
            }
            segment.mmap_segment::<M>(object)?;
            segment.copy_data(object)?;
            segment.fill_zero::<M>()?;
        }
        Ok(space)
    }

    /// Change memory protection of all segments
    ///
    /// This method adjusts the memory protection of all segments
    /// after initial mapping.
    ///
    /// # Returns
    /// * `Ok(())` - If protection changes succeed
    /// * `Err(Error)` - If protection changes fail
    fn mprotect<M: Mmap>(&self) -> Result<()> {
        let segments = self.segments();
        for segment in segments {
            segment.mprotect::<M>()?;
        }
        Ok(())
    }
}
