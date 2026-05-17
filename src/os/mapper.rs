use core::{ffi::c_void, ops::Deref};

use super::{
    MadviseAdvice, MapFlags, MappedRegion, MappedRegionControl, Mmap, MmapResult, ProtFlags,
};
use crate::{Result, sync::Arc};
use alloc::boxed::Box;

#[derive(Clone)]
pub(crate) struct Mapper(Arc<dyn Mmap>);

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

impl MappedRegionControl for Mapper {
    #[inline]
    unsafe fn munmap(&self, addr: *mut c_void, len: usize) -> Result<()> {
        unsafe { self.0.munmap(addr, len) }
    }

    #[inline]
    unsafe fn madvise(&self, addr: *mut c_void, len: usize, behavior: MadviseAdvice) -> Result<()> {
        unsafe { self.0.madvise(addr, len, behavior) }
    }

    #[inline]
    unsafe fn mprotect(&self, addr: *mut c_void, len: usize, prot: ProtFlags) -> Result<()> {
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
    unsafe fn mmap(
        &self,
        _addr: Option<usize>,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
        _offset: usize,
        _fd: Option<isize>,
    ) -> Result<MmapResult> {
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn mmap_anonymous(
        &self,
        _addr: usize,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<MappedRegion> {
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn munmap(&self, addr: *mut c_void, len: usize) -> Result<()> {
        (self.munmap)(addr, len)
    }

    unsafe fn madvise(
        &self,
        _addr: *mut c_void,
        _len: usize,
        _behavior: MadviseAdvice,
    ) -> Result<()> {
        unreachable!("MunmapAdapter only supports munmap")
    }

    unsafe fn mprotect(&self, _addr: *mut c_void, _len: usize, _prot: ProtFlags) -> Result<()> {
        unreachable!("MunmapAdapter only supports munmap")
    }
}
