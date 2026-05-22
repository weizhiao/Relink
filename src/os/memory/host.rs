use core::{
    ffi::c_void,
    ptr::{self, NonNull},
};

use crate::{
    Result,
    os::{MadviseAdvice, Mapper, Mmap, ProtFlags, VmAddr},
};

use super::{MappedRegion, RegionAccess};

/// Host-addressable mmap region.
pub struct HostRegion<M: Mmap = Mapper> {
    host_ptr: *mut c_void,
    len: usize,
    control: M,
    unmap_on_drop: bool,
}

impl MappedRegion<HostRegion> {
    #[inline]
    pub fn local<M: Mmap>(host_ptr: *mut c_void, len: usize, control: M) -> Self {
        Self::new(HostRegion::with_control(
            host_ptr,
            len,
            Mapper::new(control),
            true,
        ))
    }

    #[inline]
    pub fn local_alias<M: Mmap>(host_ptr: *mut c_void, len: usize, control: M) -> Self {
        Self::new(HostRegion::with_control(
            host_ptr,
            len,
            Mapper::new(control),
            false,
        ))
    }
}

impl<M: Mmap> HostRegion<M> {
    #[inline]
    fn with_control(host_ptr: *mut c_void, len: usize, control: M, unmap_on_drop: bool) -> Self {
        Self {
            host_ptr,
            len,
            control,
            unmap_on_drop,
        }
    }
}

impl<M: Mmap> RegionAccess for HostRegion<M> {
    #[inline]
    fn addr(&self) -> VmAddr {
        VmAddr::new(self.host_ptr as usize)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(
                self.host_ptr.cast::<u8>().add(offset),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        Ok(())
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

    #[inline]
    unsafe fn madvise(&self, offset: usize, len: usize, behavior: MadviseAdvice) -> Result<()> {
        unsafe {
            self.control.madvise(
                VmAddr::from_ptr(self.host_ptr.cast::<u8>().add(offset)),
                len,
                behavior,
            )
        }
    }

    #[inline]
    unsafe fn mprotect(&self, offset: usize, len: usize, prot: ProtFlags) -> Result<()> {
        unsafe {
            self.control.mprotect(
                VmAddr::from_ptr(self.host_ptr.cast::<u8>().add(offset)),
                len,
                prot,
            )
        }
    }
}

impl<M: Mmap> Drop for HostRegion<M> {
    fn drop(&mut self) {
        if self.unmap_on_drop {
            let _ = unsafe {
                self.control
                    .munmap(VmAddr::from_ptr(self.host_ptr), self.len)
            };
        }
    }
}

// Safety: mapped regions operate on an mmap-style allocation and delegate
// synchronization requirements to the mapping backend.
unsafe impl<M: Mmap> Send for HostRegion<M> {}
// Safety: shared access only exposes byte operations over the mapped range.
unsafe impl<M: Mmap> Sync for HostRegion<M> {}
