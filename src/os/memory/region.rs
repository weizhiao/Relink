use crate::{
    MmapError, Result,
    os::{MadviseAdvice, MappedRegionOps, ProtFlags, TargetAddr},
    sync::Arc,
};
use alloc::boxed::Box;

/// A mapped region returned by [`Mmap`](crate::os::Mmap).
#[derive(Clone)]
pub struct MappedRegion(Arc<dyn MappedRegionOps>);

impl MappedRegion {
    #[inline]
    pub fn new<O: MappedRegionOps>(ops: O) -> Self {
        Self(Arc::from(Box::new(ops) as Box<dyn MappedRegionOps>))
    }

    #[inline]
    pub fn addr(&self) -> TargetAddr {
        self.0.addr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    fn check_range(&self, offset: usize, len: usize) -> Result<()> {
        let Some(end) = offset.checked_add(len) else {
            return Err(MmapError::InvalidMappedRegionRange.into());
        };
        if end > self.len() {
            return Err(MmapError::InvalidMappedRegionRange.into());
        }
        Ok(())
    }

    /// Reads bytes from the region without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + dst.len()` is inside this region.
    #[inline]
    pub(crate) unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) {
        unsafe { self.0.read_bytes(offset, dst) }
    }

    /// Writes bytes into the region without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    #[inline]
    pub(crate) unsafe fn write_bytes(&self, offset: usize, src: &[u8]) {
        unsafe { self.0.write_bytes(offset, src) }
    }

    /// Fills bytes in the region without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    #[inline]
    pub(crate) unsafe fn zero_bytes(&self, offset: usize, len: usize) {
        unsafe { self.0.zero_bytes(offset, len) }
    }

    #[inline]
    pub unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        self.check_range(offset, len).ok()?;
        unsafe { self.0.borrow_bytes(offset, len) }
    }

    #[inline]
    pub fn madvise(&self, offset: usize, len: usize, behavior: MadviseAdvice) -> Result<()> {
        self.check_range(offset, len)?;
        unsafe { self.0.madvise(offset, len, behavior) }
    }

    #[inline]
    pub fn mprotect(&self, offset: usize, len: usize, prot: ProtFlags) -> Result<()> {
        self.check_range(offset, len)?;
        unsafe { self.0.mprotect(offset, len, prot) }
    }
}
