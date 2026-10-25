use crate::{
    MmapError, Result,
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, ProtFlags, SpaceInit, SpaceLayout},
};
use alloc::alloc::{alloc_zeroed, handle_alloc_error};
use core::{alloc::Layout, ptr::NonNull, slice::from_raw_parts_mut};

/// Allocator-backed mapping for host-addressable memory.
///
/// `AllocMmap` uses the global allocator and treats the allocation address as
/// the image VM address. It is the default mapper on bare-metal targets, but it
/// can also be selected explicitly on other platforms.
/// A non-null address passed to `create_space` selects caller-owned storage;
/// that storage is cleared for [`SpaceInit::Zeroed`]. Use `alias_space`
/// to preserve the contents of an existing image.
/// Allocated regions retain their original allocation layout and release the
/// memory on drop. Direct [`Mmap::munmap`] is unsupported because an address and
/// length alone do not identify that layout.
#[derive(Clone, Copy, Default)]
pub struct AllocMmap;

impl AllocMmap {
    /// Creates an allocator-backed mapper.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Mmap for AllocMmap {
    type Region = HostRegion;

    unsafe fn create_space(
        &self,
        layout: SpaceLayout,
        _prot: ProtFlags,
        init: SpaceInit,
    ) -> Result<MappedRegion<Self::Region>> {
        if matches!(init, SpaceInit::File { .. }) {
            return Err(crate::MmapError::FileMappingUnsupported.into());
        }
        if let Some(addr) = layout.addr.filter(|addr| *addr != VmAddr::null()) {
            if !layout.is_aligned(addr) || addr.get().checked_add(layout.len).is_none() {
                return Err(MmapError::InvalidMappedRegionRange.into());
            }
            if matches!(init, SpaceInit::Zeroed) {
                unsafe { core::ptr::write_bytes(addr.as_mut_ptr::<u8>(), 0, layout.len) };
            }
            // SAFETY: create_space's caller provides valid caller-owned storage.
            return Ok(unsafe {
                MappedRegion::local_alias_no_unmap(addr.as_mut_ptr::<u8>().cast(), layout.len)
            });
        }

        let prefix = layout.offset % layout.align;
        let allocation_len = layout
            .len
            .checked_add(prefix)
            .ok_or(MmapError::InvalidMappedRegionRange)?;
        let allocation = Layout::from_size_align(allocation_len, layout.align)
            .map_err(|_| MmapError::InvalidMappedRegionRange)?;
        let memory = NonNull::new(unsafe { alloc_zeroed(allocation) })
            .unwrap_or_else(|| handle_alloc_error(allocation));
        // The allocation is aligned already; only the requested address offset
        // separates its start from the visible image range.
        Ok(unsafe { MappedRegion::local_allocated(memory, allocation, prefix, layout.len) })
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        // SAFETY: the caller guarantees the existing storage remains valid.
        Ok(unsafe { MappedRegion::local_alias_no_unmap(addr.as_mut_ptr::<u8>().cast(), len) })
    }

    unsafe fn map_file_at(
        &self,
        _addr: VmAddr,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
        _offset: usize,
        _fd: isize,
    ) -> Result<()> {
        Err(crate::MmapError::FileMappingUnsupported.into())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<()> {
        unsafe { from_raw_parts_mut(addr.as_mut_ptr::<u8>(), len) }.fill(0);
        Ok(())
    }

    unsafe fn munmap(&self, _addr: VmAddr, _len: usize) -> Result<()> {
        // The region owns the Layout needed for deallocation.
        Err(MmapError::InvalidMappedRegionRange.into())
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_hint_allocates_memory() {
        let mapper = AllocMmap::new();
        let region = unsafe {
            mapper
                .create_space(
                    SpaceLayout {
                        addr: Some(VmAddr::null()),
                        len: mapper.page_size().bytes(),
                        align: mapper.page_size().bytes(),
                        offset: 0,
                    },
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    SpaceInit::Zeroed,
                )
                .unwrap()
        };

        assert_ne!(region.addr(), VmAddr::null());
    }
}
