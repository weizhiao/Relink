use core::{mem::size_of, ops::Range, ptr::NonNull};

use crate::{ByteRepr, Result};

use super::VmAddr;

/// Memory access backend for a mapped VM range.
///
/// The loader reads mapped bytes through [`Self::borrow_bytes`] and applies
/// relocation writes through [`Self::write_bytes`].
/// Reading requires initialized, readable bytes without concurrent writes.
/// Writing requires writable bytes and exclusive access. Buffers passed to
/// byte-copy operations must be disjoint from the accessed range.
pub trait RegionAccess: Send + Sync + 'static {
    /// Base VM address covered by this region.
    fn addr(&self) -> VmAddr;

    /// Length of this region in bytes.
    fn len(&self) -> usize;

    /// Returns true when this region contains no bytes.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writes bytes without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()>;

    /// Fills bytes with zeroes without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()>;

    /// Borrows directly readable host bytes without checking bounds.
    /// On success the slice covers exactly `offset..offset + len`. Mapped ELF
    /// metadata and byte reads through `ElfSegments` require this view.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region, keep
    /// the backing mapping alive for the returned slice, and prevent mutation of
    /// the same bytes while that slice is in use.
    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]>;

    /// Returns a host-accessible pointer without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset` is inside this region.
    unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>>;
}

/// Address-space view for an image mapped at VM addresses.
pub trait ImageMemory: Send + Sync {
    /// Returns the load base used by this image.
    fn base(&self) -> VmAddr;

    /// Returns the address range owned by this image that contains `addr`.
    ///
    /// Returns the actual mapped interval containing `addr`, excluding holes.
    /// Implementations with no mapping at `addr` return `None`.
    fn range_at(&self, addr: VmAddr) -> Option<Range<VmAddr>>;

    /// Enumerates every mapped interval, in the same precedence order as `range_at`.
    /// Empty images invoke no callbacks. Indexed mappings must remain unchanged
    /// until deregistration; changes require removing and registering the image again.
    fn visit_ranges(&self, visit: &mut dyn FnMut(Range<VmAddr>));

    /// Translates an image VM address into a host-accessible pointer.
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>>;

    /// Translates a mapped address and byte length into a host-accessible pointer.
    /// Returns `None` when the requested range is outside the host-accessible mapping.
    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>>;

    /// Reads bytes from an image VM address.
    ///
    /// # Safety
    /// The source range must be mapped, initialized, readable, and disjoint from
    /// `dst`. The caller must prevent concurrent writes to that range.
    unsafe fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()>;

    /// Writes bytes to an image VM address.
    ///
    /// # Safety
    /// The destination range must be mapped, writable, and disjoint from `src`.
    /// The caller must ensure exclusive access to the destination bytes.
    unsafe fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()>;
}

/// Typed value helpers for image memory backends.
///
/// This is split from [`ImageMemory`] so the base trait stays object-safe while
/// these generic helpers still work for `dyn ImageMemory`.
pub trait ImageMemoryExt: ImageMemory {
    /// Reads a typed value from an image VM address.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// initialized, readable image memory with no concurrent writes.
    #[inline]
    unsafe fn read_value<T: ByteRepr>(&self, addr: VmAddr) -> Result<T> {
        crate::aligned_bytes::read_value(|bytes| unsafe { self.read_bytes(addr, bytes) })
    }

    /// Writes a typed value to an image VM address.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// writable image memory with exclusive access.
    #[inline]
    unsafe fn write_value<T: ByteRepr>(&self, addr: VmAddr, value: T) -> Result<()> {
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        unsafe { self.write_bytes(addr, bytes) }
    }

    /// Reads, updates, and writes a typed value.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// initialized, readable and writable image memory with exclusive access.
    #[inline]
    unsafe fn update_value<T: ByteRepr + Copy>(
        &self,
        addr: VmAddr,
        update: impl FnOnce(T) -> T,
    ) -> Result<()> {
        if size_of::<T>() == 0 {
            return Ok(());
        }

        let value = update(unsafe { self.read_value(addr)? });
        unsafe { self.write_value(addr, value) }
    }
}

impl<M: ImageMemory + ?Sized> ImageMemoryExt for M {}

impl<M> ImageMemory for &M
where
    M: ImageMemory + ?Sized,
{
    #[inline]
    fn base(&self) -> VmAddr {
        (**self).base()
    }

    #[inline]
    fn range_at(&self, addr: VmAddr) -> Option<Range<VmAddr>> {
        (**self).range_at(addr)
    }

    #[inline]
    fn visit_ranges(&self, visit: &mut dyn FnMut(Range<VmAddr>)) {
        (**self).visit_ranges(visit)
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        (**self).host_ptr(addr)
    }

    #[inline]
    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        (**self).host_ptr_range(addr, len)
    }

    #[inline]
    unsafe fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        unsafe { (**self).read_bytes(addr, dst) }
    }

    #[inline]
    unsafe fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        unsafe { (**self).write_bytes(addr, src) }
    }
}
