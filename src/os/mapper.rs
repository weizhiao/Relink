use core::{ffi::c_void, ops::Deref};

use super::{MadviseAdvice, MapFlags, MappedRegion, Mmap, ProtFlags, VmAddr};
use crate::{Result, sync::Arc};
use alloc::boxed::Box;

/// Type-erased mmap backend used by the default loader path.
#[derive(Clone)]
pub struct Mapper(Arc<dyn Mmap>);

impl Mapper {
    #[inline]
    pub(crate) fn new<M: Mmap>(mapper: M) -> Self {
        Self(Arc::from(Box::new(mapper) as Box<dyn Mmap>))
    }

    #[inline]
    pub(crate) fn from_munmap<F>(munmap: F) -> Self
    where
        F: Fn(*mut c_void, usize) -> Result<()> + Send + Sync + 'static,
    {
        Self::new(MunmapAdapter::new(munmap))
    }
}

impl AsRef<dyn Mmap> for Mapper {
    #[inline]
    fn as_ref(&self) -> &dyn Mmap {
        self.0.as_ref()
    }
}

impl Deref for Mapper {
    type Target = dyn Mmap;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Mmap for Mapper {
    #[inline]
    fn page_size(&self) -> super::PageSize {
        self.0.page_size()
    }

    #[inline]
    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        populate_later: bool,
    ) -> Result<MappedRegion> {
        unsafe { self.0.create_space(addr, len, prot, populate_later) }
    }

    #[inline]
    unsafe fn map_file_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()> {
        unsafe { self.0.map_file_at(addr, len, prot, flags, offset, fd) }
    }

    #[inline]
    unsafe fn map_copy_at(&self, addr: VmAddr, len: usize, flags: MapFlags) -> Result<()> {
        unsafe { self.0.map_copy_at(addr, len, flags) }
    }

    #[inline]
    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<()> {
        unsafe { self.0.map_zero_at(addr, len, prot, flags) }
    }

    #[inline]
    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        unsafe { self.0.munmap(addr, len) }
    }

    #[inline]
    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()> {
        unsafe { self.0.madvise(addr, len, behavior) }
    }

    #[inline]
    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        unsafe { self.0.mprotect(addr, len, prot) }
    }
}

struct MunmapAdapter<F> {
    munmap: F,
}

impl<F> MunmapAdapter<F> {
    #[inline]
    const fn new(munmap: F) -> Self {
        Self { munmap }
    }
}

impl<F> Mmap for MunmapAdapter<F>
where
    F: Fn(*mut c_void, usize) -> Result<()> + Send + Sync + 'static,
{
    unsafe fn create_space(
        &self,
        _addr: Option<VmAddr>,
        _len: usize,
        _prot: ProtFlags,
        _populate_later: bool,
    ) -> Result<MappedRegion> {
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

    unsafe fn map_copy_at(&self, _addr: VmAddr, _len: usize, _flags: MapFlags) -> Result<()> {
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
