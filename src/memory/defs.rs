use core::{ops::Deref, ptr::NonNull};

use crate::{ByteRepr, Result, os::ProtFlags, sync::Arc, try_cast_bytes};

use super::{HostRegion, traits::RegionAccess};

/// Round up a value to the nearest power-of-two alignment boundary.
///
/// Passing `0` leaves the value unchanged.
#[inline]
pub(crate) fn roundup(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Round down a value to the nearest power-of-two alignment boundary.
#[inline]
pub(crate) fn rounddown(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

/// Round up a value to the nearest alignment boundary for any alignment.
///
/// Passing `0` leaves the value unchanged.
#[inline]
pub(crate) fn align_up(value: usize, align: usize) -> usize {
    let align = align.max(1);
    let remainder = value % align;
    if remainder == 0 {
        return value;
    }

    value
        .checked_add(align - remainder)
        .expect("alignment overflowed while rounding up value")
}

/// Virtual address in the loaded image's address space.
#[must_use = "address arithmetic returns a new value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VmAddr(usize);

/// Offset within a loaded image's virtual address space.
#[must_use = "offset arithmetic returns a new value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VmOffset(usize);

impl VmOffset {
    /// Creates a VM offset from a raw byte count.
    #[inline]
    pub const fn new(offset: usize) -> Self {
        Self(offset)
    }

    /// Returns this offset as a raw byte count.
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Adds a byte count, returning `None` on overflow.
    #[inline]
    pub fn checked_add(self, bytes: usize) -> Option<Self> {
        self.0.checked_add(bytes).map(Self)
    }

    /// Computes `self - base`, returning `None` if `self` is before `base`.
    #[inline]
    pub fn checked_offset_from(self, base: Self) -> Option<Self> {
        self.0.checked_sub(base.0).map(Self)
    }
}

impl core::fmt::Display for VmOffset {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl VmAddr {
    /// Creates a VM address from a raw integer value.
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Returns this address as a raw integer value.
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Converts a pointer value into a VM address.
    #[inline]
    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize)
    }

    /// Returns the null VM address.
    #[inline]
    pub const fn null() -> Self {
        Self(0)
    }

    /// Converts this VM address to a const pointer.
    #[inline]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Converts this VM address to a mutable pointer.
    #[inline]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    /// Rounds the address up to the nearest alignment boundary.
    ///
    /// `align` should be zero or a power of two. Passing `0` leaves the
    /// address unchanged.
    #[inline]
    pub fn roundup(self, align: usize) -> Self {
        Self(roundup(self.0, align))
    }

    /// Rounds the address down to the nearest alignment boundary.
    ///
    /// `align` should be a power of two.
    #[inline]
    pub fn rounddown(self, align: usize) -> Self {
        Self(rounddown(self.0, align))
    }

    /// Adds an offset, returning `None` on overflow.
    #[inline]
    pub fn checked_add(self, offset: VmOffset) -> Option<Self> {
        self.0.checked_add(offset.0).map(Self)
    }

    /// Computes `self - base`, returning `None` if `self` is before `base`.
    #[inline]
    pub fn checked_offset_from(self, base: Self) -> Option<VmOffset> {
        self.0.checked_sub(base.0).map(VmOffset)
    }

    /// Adds an offset with wrapping arithmetic.
    #[inline]
    pub fn wrapping_add(self, offset: VmOffset) -> Self {
        Self(self.0.wrapping_add(offset.0))
    }

    /// Subtracts an offset with wrapping arithmetic.
    #[inline]
    pub fn wrapping_sub(self, offset: VmOffset) -> Self {
        Self(self.0.wrapping_sub(offset.0))
    }

    /// Computes `self - base` with wrapping arithmetic.
    #[inline]
    pub const fn wrapping_offset_from(self, base: Self) -> VmOffset {
        VmOffset(self.0.wrapping_sub(base.0))
    }

    /// Adds a signed offset with wrapping arithmetic.
    #[inline]
    pub const fn wrapping_add_signed(self, rhs: isize) -> Self {
        Self(self.0.wrapping_add_signed(rhs))
    }
}

impl core::ops::Add<VmOffset> for VmAddr {
    type Output = Self;

    #[inline]
    fn add(self, offset: VmOffset) -> Self::Output {
        self.wrapping_add(offset)
    }
}

impl core::ops::Sub<VmOffset> for VmAddr {
    type Output = Self;

    #[inline]
    fn sub(self, offset: VmOffset) -> Self::Output {
        self.wrapping_sub(offset)
    }
}

impl core::fmt::Display for VmAddr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

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
    /// Wraps a region access backend in a shared mapped-region handle.
    #[inline]
    pub fn new(region: R) -> Self {
        Self(Arc::new(region))
    }

    /// Returns the base VM address of the mapped region.
    #[inline]
    pub fn addr(&self) -> VmAddr {
        self.0.addr()
    }

    /// Returns the mapped region length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when this region contains no bytes.
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
        if core::mem::size_of::<T>() == 0 {
            return None;
        }

        if byte_len == 0 {
            return Some(MappedView { slice: &[] });
        }

        let bytes = (unsafe { self.borrow_bytes(offset, byte_len) })?;

        Some(MappedView {
            slice: try_cast_bytes(bytes)?,
        })
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
    pub(crate) const fn from_slice(slice: &'static [T]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) const fn empty() -> Self {
        Self { slice: &[] }
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &'static [T] {
        self.slice
    }

    #[inline]
    pub(crate) fn split_at(&self, mid: usize) -> Option<(Self, Self)> {
        if mid > self.len() {
            return None;
        }
        let (head, tail) = self.slice.split_at(mid);
        Some((Self::from_slice(head), Self::from_slice(tail)))
    }
}

impl<T: 'static> Deref for MappedView<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.slice
    }
}

impl<T: 'static> AsRef<[T]> for MappedView<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self
    }
}
