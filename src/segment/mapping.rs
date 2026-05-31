use crate::input::ElfReader;
use crate::os::{MapFlags, Mmap, ProtFlags, VmAddr, VmOffset};
use crate::{Result, logging};

use super::{ElfSegment, ElfSegments};

impl ElfSegment {
    #[inline]
    fn mapping_prot(&self) -> ProtFlags {
        if self.from_relocatable {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        } else {
            self.prot
        }
    }

    #[inline]
    fn vm_addr(&self, base: VmAddr) -> VmAddr {
        base + self.offset
    }

    #[inline]
    fn segment_offset(&self, offset: usize) -> VmOffset {
        self.offset
            .checked_add(offset)
            .expect("ELF segment offset overflowed")
    }

    /// Map the segment into memory and copy bytes when direct file mapping is unavailable.
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
    fn map_segment<M>(
        &mut self,
        mapper: &M,
        object: &impl ElfReader,
        space: &ElfSegments<M::Region>,
    ) -> Result<()>
    where
        M: Mmap + ?Sized,
    {
        let len = self.len;
        let base = space.base();
        let addr = self.vm_addr(base);
        let prot = self.mapping_prot();

        debug_assert!(len.is_multiple_of(self.page_size));

        self.need_copy = true;
        if !self.from_relocatable {
            debug_assert_eq!(self.map_info.len(), 1);
            debug_assert!(self.map_info[0].offset.is_multiple_of(self.page_size));
            if let Some(fd) = object.as_fd() {
                unsafe {
                    mapper.map_file_at(addr, len, prot, self.flags, self.map_info[0].offset, fd)
                }?;
                self.need_copy = false;
            }
        }

        if self.need_copy {
            for info in &self.map_info {
                let addr = space.base() + self.segment_offset(info.start);
                let dst = space
                    .host_ptr_range(addr, info.filesz)
                    .expect("segment copy target is not host-accessible");
                let dst = unsafe { core::slice::from_raw_parts_mut(dst.as_ptr(), info.filesz) };
                object.read(dst, info.offset)?;
            }
        }

        logging::trace!(
            "[Mmap] address: {}, length: {}, flags: {:?}, zero_size: {}, map_info: {:?}",
            addr,
            len,
            prot,
            self.zero_size,
            self.map_info
        );

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
    fn mprotect<R>(&self, space: &ElfSegments<R>) -> Result<()>
    where
        R: crate::os::RegionAccess,
    {
        if self.need_copy || self.from_relocatable {
            let len = self.len;
            debug_assert!(len.is_multiple_of(self.page_size));
            let addr = self.vm_addr(space.base());
            space.mprotect(addr, len, self.prot)?;

            logging::trace!(
                "[Mprotect] address: {}, length: {}, prot: {:?}",
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
    fn fill_zero<M>(&self, mapper: &M, space: &ElfSegments<M::Region>) -> Result<()>
    where
        M: Mmap + ?Sized,
    {
        if self.zero_size > 0 {
            let zero_start = space.base() + self.segment_offset(self.content_size);
            let zero_end = zero_start.roundup(self.page_size);
            let write_len = zero_end
                .checked_offset_from(zero_start)
                .expect("ELF zero-fill range overflowed")
                .get();
            space.zero_bytes(zero_start, write_len)?;

            if write_len < self.zero_size {
                let zero_mmap_addr = zero_end;
                let zero_mmap_len = self.zero_size - write_len;
                let prot = self.mapping_prot();

                unsafe {
                    mapper.map_zero_at(
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
    fn create_space<M>(&mut self, mapper: &M) -> Result<ElfSegments<M::Region>>
    where
        M: Mmap + ?Sized;

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
    fn load_segments<M>(
        &mut self,
        mapper: &M,
        object: &impl ElfReader,
    ) -> Result<ElfSegments<M::Region>>
    where
        M: Mmap + ?Sized,
    {
        let space = self.create_space(mapper)?;
        self.create_segments()?;
        let segments = self.segments_mut();

        #[cfg(windows)]
        let base = space.base();
        #[cfg(windows)]
        let mut last_addr = space
            .primary_region()
            .map(|(memory, _)| memory as usize)
            .unwrap_or_else(|| base.get());

        for segment in segments.iter_mut() {
            #[cfg(windows)]
            if object.as_fd().is_some() {
                let addr = segment.vm_addr(base).get();
                let len = segment.len;
                if addr > last_addr {
                    crate::os::virtual_free(last_addr, addr - last_addr)?;
                }
                let space_end = space
                    .primary_region()
                    .map(|(memory, len)| memory as usize + len)
                    .unwrap_or(space.mapped_base().get() + space.mapped_len());
                if addr + len < space_end {
                    crate::os::virtual_free(addr + len, space_end - (addr + len))?;
                }
                last_addr = addr + len;
            }
            segment.map_segment(mapper, object, &space)?;
            segment.fill_zero(mapper, &space)?;
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
    fn mprotect<R>(&self, space: &ElfSegments<R>) -> Result<()>
    where
        R: crate::os::RegionAccess,
    {
        let segments = self.segments();
        for segment in segments {
            segment.mprotect(space)?;
        }
        Ok(())
    }
}
