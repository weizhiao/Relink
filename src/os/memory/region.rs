use core::{mem::size_of, ptr::NonNull};

use crate::{
    ByteRepr, Result,
    os::{ProtFlags, VmAddr},
    sync::Arc,
};

use super::{HostRegion, traits::RegionAccess};

/// A mapped region returned by [`Mmap`](crate::os::Mmap), backed by any
/// [`RegionAccess`] implementation.
pub struct MappedRegion<R: RegionAccess = HostRegion>(Arc<R>);

/// A typed borrowed view of a mapped region.
pub(crate) struct MappedView<T: 'static> {
    slice: &'static [T],
}

impl<R: RegionAccess> Clone for MappedRegion<R> {
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: 'static> Clone for MappedView<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self { slice: self.slice }
    }
}

impl<R: RegionAccess> MappedRegion<R> {
    #[inline]
    pub fn new(region: R) -> Self {
        Self(Arc::new(region))
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
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + dst.len()` is inside this region.
    #[inline]
    pub(crate) unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        unsafe { self.0.read_bytes(offset, dst) }
    }

    /// Reads one typed value from the region without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + size_of::<T>()` is inside this region
    /// and `offset` is aligned for `T`.
    #[inline]
    pub(crate) unsafe fn read_value<T: ByteRepr>(&self, offset: usize) -> Result<T> {
        unsafe { self.0.read_value(offset) }
    }

    /// Writes bytes into the region without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    #[inline]
    pub(crate) unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
        unsafe { self.0.write_bytes(offset, src) }
    }

    /// Writes one typed value into the region without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + size_of::<T>()` is inside this region
    /// and `offset` is aligned for `T`.
    #[inline]
    pub(crate) unsafe fn write_value<T: ByteRepr>(&self, offset: usize, value: T) -> Result<()> {
        unsafe { self.0.write_value(offset, value) }
    }

    /// Fills bytes in the region without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    #[inline]
    pub(crate) unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
        unsafe { self.0.zero_bytes(offset, len) }
    }

    #[inline]
    pub(crate) unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        unsafe { self.0.borrow_bytes(offset, len) }
    }

    pub(crate) fn read_view<T: ByteRepr + 'static>(
        &self,
        offset: usize,
        byte_len: usize,
    ) -> Option<MappedView<T>> {
        let elem_size = size_of::<T>();
        if elem_size == 0 || !byte_len.is_multiple_of(elem_size) {
            return None;
        }

        if byte_len == 0 {
            return Some(MappedView { slice: &[] });
        }

        let Some(bytes) = (unsafe { self.borrow_bytes(offset, byte_len) }) else {
            return None;
        };
        let (prefix, values, suffix) = unsafe { bytes.align_to::<T>() };
        if !prefix.is_empty() || !suffix.is_empty() {
            return None;
        }

        Some(MappedView { slice: values })
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

impl<T: 'static> MappedView<T> {
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self { slice: &[] }
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &'static [T] {
        self.slice
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.as_slice().len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl<T: 'static> AsRef<[T]> for MappedView<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}
