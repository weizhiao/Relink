use core::{
    ffi::c_void,
    ptr::{self, NonNull},
};

use crate::{Result, os::Mmap};

use super::{MappedRegion, MappingControl, RegionAccess, VmAddr};

/// Host-addressable mmap region.
pub struct HostRegion {
    host_ptr: *mut c_void,
    len: usize,
}

impl MappedRegion<HostRegion> {
    /// Exposes a host-backed range and unmaps the original mapping on drop.
    ///
    /// # Safety
    /// `allocation_ptr..allocation_ptr + allocation_len` must describe a valid,
    /// non-overflowing mapping or reservation owned by the caller. Ownership is
    /// transferred to the returned region: no other owner may release it, and
    /// it must remain valid until the last clone is dropped. The visible range
    /// `host_ptr..host_ptr + len` must lie within this mapping. `control` must
    /// support operations on the visible range and correctly release the original
    /// mapping through `munmap(allocation_ptr, allocation_len)`. Reserved pages
    /// must be populated with suitable permissions before access.
    #[inline]
    pub unsafe fn local<M>(
        host_ptr: *mut c_void,
        len: usize,
        allocation_ptr: *mut c_void,
        allocation_len: usize,
        control: M,
    ) -> Self
    where
        M: Mmap<Region = HostRegion>,
    {
        debug_assert!(
            (host_ptr as usize)
                .checked_sub(allocation_ptr as usize)
                .and_then(|offset| offset.checked_add(len))
                .is_some_and(|end| end <= allocation_len)
        );
        let mut control = MappingControl::from(control);
        control.owned_range = Some((VmAddr::from_ptr(allocation_ptr), allocation_len));
        Self::new(HostRegion { host_ptr, len }, Some(control))
    }

    /// Creates a host-backed mapped region alias that does not unmap on drop.
    ///
    /// # Safety
    /// `host_ptr..host_ptr + len` must describe a valid, non-overflowing mapping
    /// or address reservation. Its owner must keep it valid for the lifetime of
    /// every clone of the returned region. `control` must support operations on
    /// this range. The caller must coordinate accesses and protection changes
    /// with the owner and other aliases; pages need suitable permissions before access.
    #[inline]
    pub unsafe fn local_alias<M>(host_ptr: *mut c_void, len: usize, control: M) -> Self
    where
        M: Mmap<Region = HostRegion>,
    {
        Self::new(HostRegion { host_ptr, len }, Some(control.into()))
    }

    /// Borrows a host mapping whose owner handles protection changes and release.
    ///
    /// # Safety
    /// `host_ptr..host_ptr + len` must remain mapped and accessible for the
    /// lifetime of every clone of the returned region. The range must not overflow,
    /// and accesses must be coordinated with the owner and other aliases as for
    /// [`Self::local_alias`].
    #[inline]
    pub unsafe fn local_alias_no_unmap(host_ptr: *mut c_void, len: usize) -> Self {
        Self::new(HostRegion { host_ptr, len }, None)
    }
}

impl RegionAccess for HostRegion {
    #[inline]
    fn addr(&self) -> VmAddr {
        VmAddr::new(self.host_ptr as usize)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.host_ptr.cast::<u8>().add(offset),
                src.len(),
            );
        }
        Ok(())
    }

    #[inline]
    unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        unsafe {
            ptr::write_bytes(self.host_ptr.cast::<u8>().add(offset), 0, len);
        }
        Ok(())
    }

    #[inline]
    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        Some(unsafe { core::slice::from_raw_parts(self.host_ptr.cast::<u8>().add(offset), len) })
    }

    #[inline]
    unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>> {
        Some(unsafe { NonNull::new_unchecked(self.host_ptr.cast::<u8>().add(offset)) })
    }
}

// SAFETY: the backing remains valid across threads while a mapped handle exists.
unsafe impl Send for HostRegion {}
// SAFETY: callers of the unsafe byte operations must synchronize memory access.
unsafe impl Sync for HostRegion {}
