use crate::input::ElfReader;
use crate::os::{MapFlags, Mapper, Mmap, ProtFlags, VmAddr, VmOffset};
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
    fn mmap_segment(
        &mut self,
        mapper: &dyn Mmap,
        object: &mut impl ElfReader,
        base: VmAddr,
    ) -> Result<()> {
        let len = self.len;
        let addr = self.vm_addr(base);
        let prot = self.mapping_prot();

        debug_assert!(len.is_multiple_of(self.page_size));

        let mapped = if self.map_info.len() == 1 {
            debug_assert!(self.map_info[0].offset.is_multiple_of(self.page_size));
            unsafe {
                mapper.mmap(
                    Some(addr),
                    len,
                    prot,
                    self.flags,
                    self.map_info[0].offset,
                    object.as_fd(),
                )
            }?
        } else {
            unsafe { mapper.mmap(Some(addr), len, prot, self.flags, 0, None) }?
        };

        logging::trace!(
            "[Mmap] address: {}, length: {}, flags: {:?}, zero_size: {}, map_info: {:?}",
            addr,
            len,
            prot,
            self.zero_size,
            self.map_info
        );

        self.need_copy = mapped.needs_copy();
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
    fn copy_data(&self, space: &ElfSegments, object: &mut impl ElfReader) -> Result<()> {
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
    fn mprotect(&self, mapper: &dyn Mmap, base: VmAddr) -> Result<()> {
        if self.need_copy || self.from_relocatable {
            let len = self.len;
            debug_assert!(len.is_multiple_of(self.page_size));
            let addr = self.vm_addr(base);
            unsafe { mapper.mprotect(addr, len, self.prot) }?;

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
    fn fill_zero(&self, mapper: &dyn Mmap, space: &ElfSegments) -> Result<()> {
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
                    mapper.mmap_anonymous(
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
    fn create_space(&mut self, mapper: Mapper) -> Result<ElfSegments>;

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
    fn load_segments(
        &mut self,
        mapper: Mapper,
        object: &mut impl ElfReader,
    ) -> Result<ElfSegments> {
        let space = self.create_space(mapper.clone())?;
        self.create_segments()?;
        let segments = self.segments_mut();
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
            segment.mmap_segment(mapper.as_ref(), object, base)?;
            segment.copy_data(&space, object)?;
            segment.fill_zero(mapper.as_ref(), &space)?;
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
    fn mprotect(&self, mapper: &dyn Mmap, base: VmAddr) -> Result<()> {
        let segments = self.segments();
        for segment in segments {
            segment.mprotect(mapper, base)?;
        }
        Ok(())
    }
}
