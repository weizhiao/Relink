use core::ptr::NonNull;

use crate::{
    Result,
    os::{MadviseAdvice, ProtFlags, VmAddr},
    sync::Arc,
};

use super::HostRegion;

/// Memory access backend for a mapped VM range.
///
/// Implementations can be host-backed mmap regions, guest VM memory adapters,
/// or any other backend that can service byte reads/writes for the range.
pub trait RegionAccess: Send + Sync + 'static {
    /// Base VM address covered by this region.
    fn addr(&self) -> VmAddr;

    /// Length of this region in bytes.
    fn len(&self) -> usize;

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads bytes without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + dst.len()` is inside this region.
    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]);

    /// Writes bytes without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]);

    /// Fills bytes with zeroes without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn zero_bytes(&self, offset: usize, len: usize);

    /// Borrows directly readable host bytes without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]>;

    /// Returns a host-accessible pointer without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset` is inside this region.
    unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>>;

    /// Applies memory advice to a range without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn madvise(&self, offset: usize, len: usize, behavior: MadviseAdvice) -> Result<()>;

    /// Changes protection for a range without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn mprotect(&self, offset: usize, len: usize, prot: ProtFlags) -> Result<()>;
}

/// A mapped region returned by [`Mmap`](crate::os::Mmap), backed by any
/// [`RegionAccess`] implementation.
pub struct MappedRegion<R: RegionAccess = HostRegion>(Arc<R>);

impl<R: RegionAccess> Clone for MappedRegion<R> {
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<R: RegionAccess> MappedRegion<R> {
    #[inline]
    pub fn new(region: R) -> Self {
        Self(Arc::new(region))
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *const R {
        Arc::as_ptr(&self.0)
    }

    #[inline]
    pub fn addr(&self) -> VmAddr {
        self.0.addr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    pub(crate) unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        unsafe { self.0.borrow_bytes(offset, len) }
    }

    /// Returns a host-accessible pointer without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset` is inside this region.
    #[inline]
    pub(crate) unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>> {
        unsafe { self.0.host_ptr(offset) }
    }

    #[inline]
    pub(crate) unsafe fn mprotect(&self, offset: usize, len: usize, prot: ProtFlags) -> Result<()> {
        unsafe { self.0.mprotect(offset, len, prot) }
    }
}
