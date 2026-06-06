use core::{
    mem::{MaybeUninit, size_of},
    ptr::NonNull,
};

use crate::{
    ByteRepr, Result,
    os::{MadviseAdvice, ProtFlags, VmAddr},
};

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
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + dst.len()` is inside this region.
    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()>;

    /// Reads one typed value without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + size_of::<T>()` is inside this region
    /// and `offset` is aligned for `T`.
    #[inline]
    unsafe fn read_value<T: ByteRepr>(&self, offset: usize) -> Result<T> {
        unsafe { self.read_unaligned_value(offset) }
    }

    /// Reads one typed value without requiring alignment.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + size_of::<T>()` is inside this region.
    #[inline]
    unsafe fn read_unaligned_value<T: ByteRepr>(&self, offset: usize) -> Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>())
        };
        unsafe { self.read_bytes(offset, bytes)? };
        Ok(unsafe { value.assume_init() })
    }

    /// Writes bytes without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()>;

    /// Writes one typed value without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + size_of::<T>()` is inside this region
    /// and `offset` is aligned for `T`.
    #[inline]
    unsafe fn write_value<T: ByteRepr>(&self, offset: usize, value: T) -> Result<()> {
        unsafe { self.write_unaligned_value(offset, value) }
    }

    /// Writes one typed value without requiring alignment.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + size_of::<T>()` is inside this region.
    #[inline]
    unsafe fn write_unaligned_value<T: ByteRepr>(&self, offset: usize, value: T) -> Result<()> {
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        unsafe { self.write_bytes(offset, bytes) }
    }

    /// Fills bytes with zeroes without checking bounds.
    ///
    /// The returned error represents backend access failure; it is not a
    /// substitute for range validation.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()>;

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

/// Address-space view for an image mapped at VM addresses.
pub trait ImageMemory: Send + Sync {
    /// Returns the load base used by this image.
    fn base(&self) -> VmAddr;

    /// Translates an image VM address into a host-accessible pointer.
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>>;

    /// Reads bytes from an image VM address.
    fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()>;

    /// Writes bytes to an image VM address.
    fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()>;

    /// Writes a typed value to an image VM address.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// writable image memory.
    #[inline]
    unsafe fn write_value<T: ByteRepr>(&self, addr: VmAddr, value: T) -> Result<()>
    where
        Self: Sized,
    {
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        self.write_bytes(addr, bytes)
    }

    /// Reads, updates, and writes a typed value.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// readable and writable image memory.
    #[inline]
    unsafe fn update_value<T: ByteRepr + Copy>(
        &self,
        addr: VmAddr,
        update: impl FnOnce(T) -> T,
    ) -> Result<()>
    where
        Self: Sized,
    {
        if size_of::<T>() == 0 {
            return Ok(());
        }

        let mut value = MaybeUninit::<T>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>())
        };
        self.read_bytes(addr, bytes)?;
        let value = update(unsafe { value.assume_init() });
        unsafe { self.write_value(addr, value) }
    }
}

impl<M> ImageMemory for &M
where
    M: ImageMemory + ?Sized,
{
    #[inline]
    fn base(&self) -> VmAddr {
        (**self).base()
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        (**self).host_ptr(addr)
    }

    #[inline]
    fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        (**self).read_bytes(addr, dst)
    }

    #[inline]
    fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        (**self).write_bytes(addr, src)
    }
}
