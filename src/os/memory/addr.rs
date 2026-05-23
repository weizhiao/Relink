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
    #[inline]
    pub const fn new(offset: usize) -> Self {
        Self(offset)
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
    pub fn checked_offset_from(self, base: Self) -> Option<usize> {
        self.0.checked_sub(base.0)
    }

    #[inline]
    pub fn saturating_offset_from(self, base: Self) -> usize {
        self.0.saturating_sub(base.0)
    }
}

impl VmAddr {
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    #[inline]
    pub(crate) const fn into_inner(self) -> usize {
        self.0
    }

    #[inline]
    pub(crate) fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize)
    }

    #[inline]
    pub(crate) fn null() -> Self {
        Self::from_ptr(core::ptr::null::<()>())
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub(crate) const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub fn checked_add(self, offset: VmOffset) -> Option<Self> {
        self.0.checked_add(offset.0).map(Self)
    }

    #[inline]
    pub fn checked_offset_from(self, base: Self) -> Option<VmOffset> {
        self.0.checked_sub(base.0).map(VmOffset)
    }

    #[inline]
    pub fn wrapping_add(self, offset: VmOffset) -> Self {
        Self(self.0.wrapping_add(offset.0))
    }

    #[inline]
    pub fn wrapping_sub(self, offset: VmOffset) -> Self {
        Self(self.0.wrapping_sub(offset.0))
    }

    #[inline]
    pub(crate) const fn wrapping_offset_from(self, base: Self) -> VmOffset {
        VmOffset(self.0.wrapping_sub(base.0))
    }

    #[inline]
    pub(crate) const fn addend(self, rhs: isize) -> Self {
        Self(self.0.wrapping_add_signed(rhs))
    }

    #[inline]
    #[cfg(any(feature = "tls", feature = "object"))]
    pub(crate) const fn relative_to(self, place: usize) -> Self {
        Self(self.0.wrapping_sub(place))
    }
}

impl core::fmt::LowerHex for VmAddr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl core::fmt::UpperHex for VmAddr {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.0, f)
    }
}
