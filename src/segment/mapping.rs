use crate::input::{ElfReader, FileBacking};
use crate::memory::{ImageMemory, RegionAccess, VmAddr, VmOffset, roundup};
use crate::os::{MapFlags, Mmap, ProtFlags};
use crate::{Result, logging};

use super::{CopyRegion, ElfSegment, ElfSegments, SegmentContent};
use core::borrow::Borrow;

impl ElfSegment {
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

    /// Maps the contiguous file data of a program-header segment.
    fn map_file<M: Mmap + ?Sized>(
        &self,
        mapper: &M,
        space: &ElfSegments<M::Region>,
        backing: FileBacking,
        file_offset: usize,
        file_size: usize,
    ) -> Result<()> {
        debug_assert!(self.len.is_multiple_of(self.page_size));
        debug_assert!(file_offset.is_multiple_of(self.page_size));
        if file_size != 0 {
            let offset = backing
                .offset
                .checked_add(file_offset)
                .ok_or(crate::IoError::ReadBufferTooLarge)?;
            unsafe {
                mapper.map_file_at(
                    self.vm_addr(space.base()),
                    roundup(file_size, self.page_size),
                    self.prot,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    offset,
                    backing.fd,
                )
            }?;
        }
        Ok(())
    }

    /// Copies the segment's file regions into an existing writable space.
    fn copy_data<R: RegionAccess>(
        &self,
        object: &impl ElfReader,
        space: &ElfSegments<R>,
    ) -> Result<()> {
        let copy = |region: &CopyRegion| -> Result<()> {
            let addr = space.base() + self.segment_offset(region.segment_offset);
            let dst = space
                .host_ptr_range(addr, region.len)
                .expect("segment copy target is not host-accessible");
            let dst = unsafe { core::slice::from_raw_parts_mut(dst.as_ptr(), region.len) };
            object.read(dst, region.file_offset)
        };
        match &self.content {
            SegmentContent::Contiguous {
                file_offset,
                file_size,
                ..
            } => copy(&CopyRegion {
                file_offset: *file_offset,
                segment_offset: 0,
                len: *file_size,
            })?,
            SegmentContent::Scattered(regions) => {
                for region in regions {
                    copy(region)?;
                }
            }
        }
        Ok(())
    }

    /// Clears the file-backed page tail and populates the remaining BSS pages.
    pub(super) fn fill_zero<M: Mmap + ?Sized>(
        &self,
        mapper: &M,
        space: &ElfSegments<M::Region>,
        file_size: usize,
        zero_size: usize,
    ) -> Result<()> {
        if zero_size > 0 {
            let zero_start = space.base() + self.segment_offset(file_size);
            let zero_end = zero_start.roundup(self.page_size);
            let write_len = zero_end
                .checked_offset_from(zero_start)
                .expect("ELF zero-fill range overflowed")
                .get();
            // Clear through the page boundary, including padding past p_memsz.
            // ld.so's bootstrap allocator uses that padding as zeroed storage.
            if write_len != 0 {
                if self.prot.contains(ProtFlags::PROT_WRITE) {
                    space.zero_bytes(zero_start, write_len)?;
                } else {
                    let page_start = zero_start.rounddown(self.page_size);
                    space.mprotect(
                        page_start,
                        self.page_size,
                        self.prot | ProtFlags::PROT_WRITE,
                    )?;
                    let cleared = space.zero_bytes(zero_start, write_len);
                    // Restore the original permissions even if the region's
                    // zeroing operation reports an error.
                    let restored = space.mprotect(page_start, self.page_size, self.prot);
                    cleared?;
                    restored?;
                }
            }

            if write_len < zero_size {
                unsafe {
                    mapper.map_zero_at(
                        zero_end,
                        self.len - roundup(file_size, self.page_size),
                        self.prot,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    )
                }?;
            }
        }
        Ok(())
    }
}

/// Populates a reserved image from immutable segment layouts.
/// File-backed program segments use direct mappings; other inputs copy into
/// writable memory created with [`crate::os::SpaceInit::Zeroed`].
/// Callers retain control of subsequent protection changes.
pub(crate) fn populate_segments<M: Mmap + ?Sized>(
    mapper: &M,
    object: &impl ElfReader,
    space: &ElfSegments<M::Region>,
    segments: impl IntoIterator<Item = impl Borrow<ElfSegment>>,
    backing: Option<FileBacking>,
) -> Result<()> {
    if let Some(backing) = backing {
        for segment in segments {
            let segment = segment.borrow();
            let SegmentContent::Contiguous {
                file_offset,
                file_size,
                zero_size,
            } = &segment.content
            else {
                unreachable!("scattered segment content requires a writable copy space");
            };
            segment.map_file(mapper, space, backing, *file_offset, *file_size)?;
            segment.fill_zero(mapper, space, *file_size, *zero_size)?;
            logging::trace!(
                "[Mmap] address: {}, length: {}, flags: {:?}",
                segment.vm_addr(space.base()),
                segment.len,
                segment.prot
            );
        }
    } else {
        for segment in segments {
            let segment = segment.borrow();
            segment.copy_data(object, space)?;
            logging::trace!(
                "[Copy] address: {}, length: {}, content: {:?}",
                segment.vm_addr(space.base()),
                segment.len,
                segment.content
            );
        }
    }
    Ok(())
}

/// Applies the segment permissions at the caller's chosen lifecycle stage.
pub(crate) fn protect_segments<R: RegionAccess>(
    space: &ElfSegments<R>,
    segments: impl IntoIterator<Item = impl Borrow<ElfSegment>>,
) -> Result<()> {
    for segment in segments {
        let segment = segment.borrow();
        debug_assert!(segment.len.is_multiple_of(segment.page_size));
        let addr = segment.vm_addr(space.base());
        space.mprotect(addr, segment.len, segment.prot)?;
        logging::trace!(
            "[Mprotect] address: {}, length: {}, prot: {:?}",
            addr,
            segment.len,
            segment.prot
        );
    }
    Ok(())
}
