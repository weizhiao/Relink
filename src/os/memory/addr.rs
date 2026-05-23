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
    #[inline]
    pub const fn new(offset: usize) -> Self {
        Self(offset)
    }

    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    #[inline]
    pub fn checked_add(self, bytes: usize) -> Option<Self> {
        self.0.checked_add(bytes).map(Self)
    }

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
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    #[inline]
    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize)
    }

    #[inline]
    pub const fn null() -> Self {
        Self(0)
    }

    #[inline]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

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
    pub const fn wrapping_offset_from(self, base: Self) -> VmOffset {
        VmOffset(self.0.wrapping_sub(base.0))
    }

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
