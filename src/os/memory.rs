use core::{ffi::c_void, mem::size_of, ptr};

use crate::{ByteRepr, MmapError, Result, sync::Arc};
use alloc::boxed::Box;

/// Address in a mapped target region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TargetAddr(usize);

impl TargetAddr {
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    #[inline]
    pub fn checked_add(self, offset: usize) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    #[inline]
    pub fn wrapping_add(self, offset: usize) -> Self {
        Self(self.0.wrapping_add(offset))
    }

    #[inline]
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

/// Result of an mmap-style operation.
pub struct MmapResult {
    region: MappedRegion,
    needs_copy: bool,
}

impl MmapResult {
    #[inline]
    pub fn new(region: MappedRegion, needs_copy: bool) -> Self {
        Self { region, needs_copy }
    }

    #[inline]
    pub fn region(&self) -> &MappedRegion {
        &self.region
    }

    #[inline]
    pub fn into_region(self) -> MappedRegion {
        self.region
    }

    #[inline]
    pub const fn needs_copy(&self) -> bool {
        self.needs_copy
    }

    #[inline]
    pub fn into_parts(self) -> (MappedRegion, bool) {
        (self.region, self.needs_copy)
    }
}

/// Memory-mapping control operations used by the default local-region adapter.
pub trait MappedRegionControl: Send + Sync + 'static {
    /// Unmaps the whole region.
    ///
    /// # Safety
    /// `addr` and `len` must describe a region allocated by this control object.
    unsafe fn munmap(&self, addr: *mut c_void, len: usize) -> Result<()>;

    /// Applies memory advice to a range.
    ///
    /// # Safety
    /// `addr..addr + len` must be valid for this mapping backend.
    unsafe fn madvise(
        &self,
        addr: *mut c_void,
        len: usize,
        behavior: crate::os::MadviseAdvice,
    ) -> Result<()>;

    /// Changes protection for a range.
    ///
    /// # Safety
    /// `addr..addr + len` must be valid for this mapping backend.
    unsafe fn mprotect(
        &self,
        addr: *mut c_void,
        len: usize,
        prot: crate::os::ProtFlags,
    ) -> Result<()>;
}

/// Operations supported by one mapped region.
pub trait MappedRegionOps: Send + Sync + 'static {
    /// Base target address of this mapping.
    fn addr(&self) -> TargetAddr;

    /// Length of this mapping in bytes.
    fn len(&self) -> usize;

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

    /// Reads bytes from the mapping at `offset`.
    fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        self.check_range(offset, dst.len())?;
        unsafe { self.read_bytes_unchecked(offset, dst) }
    }

    /// Reads bytes from the mapping without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + dst.len()` is inside this region.
    unsafe fn read_bytes_unchecked(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(
                self.addr().wrapping_add(offset).as_ptr(),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        Ok(())
    }

    /// Writes bytes into the mapping at `offset`.
    fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
        self.check_range(offset, src.len())?;
        unsafe { self.write_bytes_unchecked(offset, src) }
    }

    /// Writes bytes into the mapping without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    unsafe fn write_bytes_unchecked(&self, offset: usize, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.addr().wrapping_add(offset).as_mut_ptr(),
                src.len(),
            );
        }
        Ok(())
    }

    /// Fills bytes in the mapping with zeroes.
    fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
        self.check_range(offset, len)?;
        unsafe { self.zero_bytes_unchecked(offset, len) }
    }

    /// Fills bytes in the mapping with zeroes without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn zero_bytes_unchecked(&self, offset: usize, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        unsafe {
            ptr::write_bytes(self.addr().wrapping_add(offset).as_mut_ptr::<u8>(), 0, len);
        }
        Ok(())
    }

    /// Borrows mapped bytes when they are directly readable as Rust memory.
    ///
    /// # Safety
    /// Implementations may only return `Some` when the byte range remains
    /// readable through the returned lifetime.
    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        self.check_range(offset, len).ok()?;
        unsafe { self.borrow_bytes_unchecked(offset, len) }
    }

    /// Borrows mapped bytes without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    /// Implementations may only return `Some` when the byte range remains
    /// readable through the returned lifetime.
    unsafe fn borrow_bytes_unchecked(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        Some(unsafe {
            core::slice::from_raw_parts(self.addr().wrapping_add(offset).as_ptr::<u8>(), len)
        })
    }

    /// Applies memory advice to a range.
    fn madvise(&self, offset: usize, len: usize, behavior: crate::os::MadviseAdvice) -> Result<()> {
        self.check_range(offset, len)?;
        unsafe { self.madvise_unchecked(offset, len, behavior) }
    }

    /// Applies memory advice to a range without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn madvise_unchecked(
        &self,
        offset: usize,
        len: usize,
        behavior: crate::os::MadviseAdvice,
    ) -> Result<()>;

    /// Changes protection for a range.
    fn mprotect(&self, offset: usize, len: usize, prot: crate::os::ProtFlags) -> Result<()> {
        self.check_range(offset, len)?;
        unsafe { self.mprotect_unchecked(offset, len, prot) }
    }

    /// Changes protection for a range without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    unsafe fn mprotect_unchecked(
        &self,
        offset: usize,
        len: usize,
        prot: crate::os::ProtFlags,
    ) -> Result<()>;
}

/// A mapped region returned by [`Mmap`](crate::os::Mmap).
#[derive(Clone)]
pub struct MappedRegion(Arc<dyn MappedRegionOps>);

impl MappedRegion {
    #[inline]
    pub fn new<O: MappedRegionOps>(ops: O) -> Self {
        Self(Arc::from(Box::new(ops) as Box<dyn MappedRegionOps>))
    }

    #[inline]
    pub fn local<C: MappedRegionControl>(addr: *mut c_void, len: usize, control: C) -> Self {
        Self::new(LocalMappedRegion {
            addr,
            len,
            control,
            unmap_on_drop: true,
        })
    }

    #[inline]
    pub fn local_alias<C: MappedRegionControl>(addr: *mut c_void, len: usize, control: C) -> Self {
        Self::new(LocalMappedRegion {
            addr,
            len,
            control,
            unmap_on_drop: false,
        })
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
    pub fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        self.0.read_bytes(offset, dst)
    }

    #[inline]
    pub fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
        self.0.write_bytes(offset, src)
    }

    #[inline]
    pub fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
        self.0.zero_bytes(offset, len)
    }

    #[inline]
    pub unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        unsafe { self.0.borrow_bytes(offset, len) }
    }

    /// Reads bytes from the region without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + dst.len()` is inside this region.
    #[inline]
    pub(crate) unsafe fn read_bytes_unchecked(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        unsafe { self.0.read_bytes_unchecked(offset, dst) }
    }

    /// Writes bytes into the region without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + src.len()` is inside this region.
    #[inline]
    pub(crate) unsafe fn write_bytes_unchecked(&self, offset: usize, src: &[u8]) -> Result<()> {
        unsafe { self.0.write_bytes_unchecked(offset, src) }
    }

    /// Fills bytes in the region without checking bounds.
    ///
    /// # Safety
    /// The caller must ensure `offset..offset + len` is inside this region.
    #[inline]
    pub(crate) unsafe fn zero_bytes_unchecked(&self, offset: usize, len: usize) -> Result<()> {
        unsafe { self.0.zero_bytes_unchecked(offset, len) }
    }

    #[inline]
    pub fn madvise(
        &self,
        offset: usize,
        len: usize,
        behavior: crate::os::MadviseAdvice,
    ) -> Result<()> {
        self.0.madvise(offset, len, behavior)
    }

    #[inline]
    pub fn mprotect(&self, offset: usize, len: usize, prot: crate::os::ProtFlags) -> Result<()> {
        self.0.mprotect(offset, len, prot)
    }
}

struct LocalMappedRegion<C: MappedRegionControl> {
    addr: *mut c_void,
    len: usize,
    control: C,
    unmap_on_drop: bool,
}

impl<C: MappedRegionControl> MappedRegionOps for LocalMappedRegion<C> {
    #[inline]
    fn addr(&self) -> TargetAddr {
        TargetAddr::new(self.addr as usize)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    unsafe fn madvise_unchecked(
        &self,
        offset: usize,
        len: usize,
        behavior: crate::os::MadviseAdvice,
    ) -> Result<()> {
        unsafe {
            self.control
                .madvise(self.addr.cast::<u8>().add(offset).cast(), len, behavior)
        }
    }

    #[inline]
    unsafe fn mprotect_unchecked(
        &self,
        offset: usize,
        len: usize,
        prot: crate::os::ProtFlags,
    ) -> Result<()> {
        unsafe {
            self.control
                .mprotect(self.addr.cast::<u8>().add(offset).cast(), len, prot)
        }
    }
}

impl<C: MappedRegionControl> Drop for LocalMappedRegion<C> {
    fn drop(&mut self) {
        if self.unmap_on_drop {
            let _ = unsafe { self.control.munmap(self.addr, self.len) };
        }
    }
}

// Safety: local mapped regions operate on an owned mmap-style allocation and
// delegate synchronization requirements to the mapping backend.
unsafe impl<C: MappedRegionControl> Send for LocalMappedRegion<C> {}
// Safety: shared access only exposes byte operations over the mapped range.
unsafe impl<C: MappedRegionControl> Sync for LocalMappedRegion<C> {}

/// A typed borrowed view of a mapped region.
pub(crate) struct MappedView<T: 'static> {
    source_addr: TargetAddr,
    slice: &'static [T],
}

impl<T: 'static> Clone for MappedView<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            source_addr: self.source_addr,
            slice: self.slice,
        }
    }
}

impl<T: 'static> MappedView<T> {
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            source_addr: TargetAddr::new(0),
            slice: &[],
        }
    }

    pub(crate) fn read_region(
        region: &MappedRegion,
        offset: usize,
        source_addr: TargetAddr,
        byte_len: usize,
    ) -> Result<Option<Self>>
    where
        T: ByteRepr,
    {
        let elem_size = size_of::<T>();
        if elem_size == 0 || !byte_len.is_multiple_of(elem_size) {
            return Ok(None);
        }

        if byte_len == 0 {
            return Ok(Some(Self {
                source_addr,
                slice: &[],
            }));
        }

        let Some(bytes) = (unsafe { region.borrow_bytes(offset, byte_len) }) else {
            return Ok(None);
        };
        let (prefix, values, suffix) = unsafe { bytes.align_to::<T>() };
        if !prefix.is_empty() || !suffix.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            source_addr,
            slice: values,
        }))
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

    #[inline]
    pub(crate) fn source_end(&self) -> Option<TargetAddr> {
        let byte_len = self.len().checked_mul(size_of::<T>())?;
        self.source_addr.checked_add(byte_len)
    }
}

impl<T: 'static> AsRef<[T]> for MappedView<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}
