/// Virtual address in the loaded image's address space.
#[must_use = "address arithmetic returns a new value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VmAddr(usize);

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
    pub(crate) const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub(crate) const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
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
    pub(crate) const fn offset(self, rhs: usize) -> Self {
        Self(self.0.wrapping_add(rhs))
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
