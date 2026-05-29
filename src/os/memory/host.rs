use core::{
    ffi::c_void,
    mem::{MaybeUninit, align_of, size_of},
    ptr::{self, NonNull},
};

use alloc::boxed::Box;

use crate::{
    ByteRepr, Result,
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags, VmAddr},
};

use super::{MappedRegion, RegionAccess};

/// Host-addressable mmap region.
pub struct HostRegion {
    host_ptr: *mut c_void,
    len: usize,
    control: Box<dyn Mmap<Region = HostRegion>>,
    unmap_on_drop: bool,
}

impl MappedRegion<HostRegion> {
    #[inline]
    pub fn local<M>(host_ptr: *mut c_void, len: usize, control: M) -> Self
    where
        M: Mmap<Region = HostRegion>,
    {
        Self::new(HostRegion::with_control(
            host_ptr,
            len,
            Box::new(control),
            true,
        ))
    }

    #[inline]
    pub fn local_alias<M>(host_ptr: *mut c_void, len: usize, control: M) -> Self
    where
        M: Mmap<Region = HostRegion>,
    {
        Self::new(HostRegion::with_control(
            host_ptr,
            len,
            Box::new(control),
            false,
        ))
    }

    #[inline]
    pub(crate) fn local_with_munmap<F>(host_ptr: *mut c_void, len: usize, munmap: F) -> Self
    where
        F: Fn(*mut c_void, usize) -> Result<()> + Send + Sync + 'static,
    {
        Self::local(host_ptr, len, MunmapAdapter { munmap })
    }

    #[inline]
    pub(crate) fn local_alias_no_unmap(host_ptr: *mut c_void, len: usize) -> Self {
        Self::local_alias(host_ptr, len, NoopMmap)
    }
}

impl HostRegion {
    #[inline]
    fn with_control(
        host_ptr: *mut c_void,
        len: usize,
        control: Box<dyn Mmap<Region = HostRegion>>,
        unmap_on_drop: bool,
    ) -> Self {
        Self {
            host_ptr,
            len,
            control,
            unmap_on_drop,
        }
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
    unsafe fn read_value<T: ByteRepr>(&self, offset: usize) -> Result<T> {
        if size_of::<T>() == 0 {
            return Ok(unsafe { MaybeUninit::<T>::zeroed().assume_init() });
        }
        let ptr = unsafe { self.host_ptr.cast::<u8>().add(offset).cast::<T>() };
        debug_assert!((ptr as usize).is_multiple_of(align_of::<T>()));
        Ok(unsafe { ptr::read(ptr) })
    }

    #[inline]
    unsafe fn write_value<T: ByteRepr>(&self, offset: usize, value: T) -> Result<()> {
        if size_of::<T>() == 0 {
            return Ok(());
        }
        let ptr = unsafe { self.host_ptr.cast::<u8>().add(offset).cast::<T>() };
        debug_assert!((ptr as usize).is_multiple_of(align_of::<T>()));
        unsafe {
            ptr::write(ptr, value);
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

impl Drop for HostRegion {
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
unsafe impl Send for HostRegion {}
// Safety: shared access only exposes byte operations over the mapped range.
unsafe impl Sync for HostRegion {}

struct MunmapAdapter<F> {
    munmap: F,
}

impl<F> Mmap for MunmapAdapter<F>
where
    F: Fn(*mut c_void, usize) -> Result<()> + Send + Sync + 'static,
{
    type Region = HostRegion;

    unsafe fn create_space(
        &self,
        _addr: Option<VmAddr>,
        _len: usize,
        _prot: ProtFlags,
        _populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>> {
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn alias_space(&self, _addr: VmAddr, _len: usize) -> Result<MappedRegion<Self::Region>> {
        unreachable!("MunmapAdapter only supports munmap")
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
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn map_zero_at(
        &self,
        _addr: VmAddr,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<()> {
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        (self.munmap)(addr.as_mut_ptr(), len)
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
        unreachable!("MunmapAdapter only supports munmap")
    }
}

struct NoopMmap;

impl Mmap for NoopMmap {
    type Region = HostRegion;

    fn page_size(&self) -> PageSize {
        PageSize::Base
    }

    unsafe fn create_space(
        &self,
        _addr: Option<VmAddr>,
        _len: usize,
        _prot: ProtFlags,
        _populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>> {
        unreachable!("NoopMmap only supports borrowed aliases")
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        Ok(MappedRegion::local_alias_no_unmap(addr.as_mut_ptr(), len))
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
        unreachable!("NoopMmap only supports borrowed aliases")
    }

    unsafe fn map_zero_at(
        &self,
        _addr: VmAddr,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<()> {
        unreachable!("NoopMmap only supports borrowed aliases")
    }

    unsafe fn munmap(&self, _addr: VmAddr, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
        Ok(())
    }
}
