use crate::{
    MmapError, Result,
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, ProtFlags, SpaceInit, SpaceLayout},
};
use alloc::alloc::{alloc, dealloc, handle_alloc_error};
use core::{alloc::Layout, ptr::NonNull, slice::from_raw_parts_mut};

/// Allocator-backed mapping for host-addressable memory.
///
/// `AllocMmap` uses the global allocator and exposes host addresses to the
/// loaded image. It is the default mapper on bare-metal targets, but it
/// can also be selected explicitly on other platforms.
/// A non-null address passed to `create_space` selects caller-owned storage;
/// that storage is cleared for [`SpaceInit::Zeroed`]. Use `alias_space`
/// to preserve the contents of an existing image.
/// Owned storage is allocated at the backend's base page alignment. Larger
/// image alignments use padding. The last handle releases the original allocation.
#[derive(Clone, Copy, Default)]
pub struct AllocMmap;

impl AllocMmap {
    /// Creates an allocator-backed mapper.
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    fn allocation_layout(&self, len: usize) -> Result<Layout> {
        Layout::from_size_align(len, self.page_size().bytes())
            .map_err(|_| MmapError::InvalidMappedRegionRange.into())
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
            if !layout.is_aligned(addr) {
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

        let allocation_len = layout.reservation_len(self.page_size().bytes())?;
        let allocation = self.allocation_layout(allocation_len)?;
        let memory = NonNull::new(unsafe { alloc(allocation) })
            .unwrap_or_else(|| handle_alloc_error(allocation));
        let base = memory.as_ptr();
        let prefix = layout.padding_at(VmAddr::from_ptr(base));
        unsafe {
            let visible = base.add(prefix);
            visible.write_bytes(0, layout.len);
            Ok(MappedRegion::local(
                visible.cast(),
                layout.len,
                base.cast(),
                allocation_len,
                *self,
            ))
        }
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        // SAFETY: the caller guarantees the existing storage remains valid.
        Ok(unsafe { MappedRegion::local_alias_no_unmap(addr.as_mut_ptr::<u8>().cast(), len) })
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

    /// Releases the original global allocation, including its alignment padding.
    ///
    /// # Safety
    /// `addr` and `len` must match the original allocation returned by the global
    /// allocator for this backend. The caller must have exclusive ownership of it.
    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        let allocation = self.allocation_layout(len)?;
        unsafe { dealloc(addr.as_mut_ptr(), allocation) };
        Ok(())
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
        Ok(())
    }
}
