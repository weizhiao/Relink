use core::{ffi::c_void, ptr};

use crate::{
    Result,
    os::{MadviseAdvice, MappedRegionOps, Mmap, ProtFlags, TargetAddr},
};

use super::MappedRegion;

impl MappedRegion {
    #[inline]
    pub fn local<M: Mmap>(addr: *mut c_void, len: usize, control: M) -> Self {
        Self::new(LocalMappedRegion {
            addr,
            len,
            control,
            unmap_on_drop: true,
        })
    }

    #[inline]
    pub fn local_alias<M: Mmap>(addr: *mut c_void, len: usize, control: M) -> Self {
        Self::new(LocalMappedRegion {
            addr,
            len,
            control,
            unmap_on_drop: false,
        })
    }
}

struct LocalMappedRegion<M: Mmap> {
    addr: *mut c_void,
    len: usize,
    control: M,
    unmap_on_drop: bool,
}

impl<M: Mmap> MappedRegionOps for LocalMappedRegion<M> {
    #[inline]
    fn addr(&self) -> TargetAddr {
        TargetAddr::new(self.addr as usize)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) {
        if dst.is_empty() {
            return;
        }
        unsafe {
            ptr::copy_nonoverlapping(
                self.addr.cast::<u8>().add(offset),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
    }

    #[inline]
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) {
        if src.is_empty() {
            return;
        }
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.addr.cast::<u8>().add(offset), src.len());
        }
    }

    #[inline]
    unsafe fn zero_bytes(&self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        unsafe {
            ptr::write_bytes(self.addr.cast::<u8>().add(offset), 0, len);
        }
    }

    #[inline]
    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        Some(unsafe { core::slice::from_raw_parts(self.addr.cast::<u8>().add(offset), len) })
    }

    #[inline]
    unsafe fn madvise(&self, offset: usize, len: usize, behavior: MadviseAdvice) -> Result<()> {
        unsafe {
            self.control
                .madvise(self.addr.cast::<u8>().add(offset).cast(), len, behavior)
        }
    }

    #[inline]
    unsafe fn mprotect(&self, offset: usize, len: usize, prot: ProtFlags) -> Result<()> {
        unsafe {
            self.control
                .mprotect(self.addr.cast::<u8>().add(offset).cast(), len, prot)
        }
    }
}

impl<M: Mmap> Drop for LocalMappedRegion<M> {
    fn drop(&mut self) {
        if self.unmap_on_drop {
            let _ = unsafe { self.control.munmap(self.addr, self.len) };
        }
    }
}

// Safety: local mapped regions operate on an owned mmap-style allocation and
// delegate synchronization requirements to the mapping backend.
unsafe impl<M: Mmap> Send for LocalMappedRegion<M> {}
// Safety: shared access only exposes byte operations over the mapped range.
unsafe impl<M: Mmap> Sync for LocalMappedRegion<M> {}
