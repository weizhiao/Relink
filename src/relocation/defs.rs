#[cfg(feature = "object")]
use crate::{RelocationError, Result};
use core::ptr::null;

/// A wrapper type for relocation values, providing type safety and arithmetic operations.
///
/// This type represents computed addresses or offsets used in relocations.
/// It supports addition and subtraction for address calculations.
#[must_use = "relocation arithmetic returns a new value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct RelocValue<T>(T);

pub(crate) type RelocAddr = RelocValue<usize>;
#[cfg(feature = "object")]
pub(crate) type RelocSWord32 = RelocValue<i32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationValueFormula {
    Absolute,
    RelativeToPlace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationValueKind {
    None,
    Address(RelocationValueFormula),
    Word32(RelocationValueFormula),
    SWord32(RelocationValueFormula),
}

impl<T> RelocValue<T> {
    #[inline]
    pub const fn new(val: T) -> Self {
        Self(val)
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl RelocAddr {
    #[inline]
    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize)
    }

    #[inline]
    pub fn null() -> Self {
        Self::from_ptr(null::<()>())
    }

    #[inline]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub const fn offset(self, rhs: usize) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    #[inline]
    pub const fn addend(self, rhs: isize) -> Self {
        Self(self.0.wrapping_add_signed(rhs))
    }

    #[inline]
    #[cfg(any(feature = "tls", feature = "object"))]
    pub const fn relative_to(self, place: usize) -> Self {
        Self(self.0.wrapping_sub(place))
    }

    #[inline]
    #[cfg(feature = "object")]
    pub fn try_into_sword32(self) -> Result<RelocSWord32> {
        i32::try_from(self.0 as isize)
            .map(RelocValue::new)
            .map_err(|_| RelocationError::IntegerConversionOverflow.into())
    }
}

impl RelocationValueFormula {
    #[inline]
    pub(crate) fn compute(self, target: usize, addend: isize, place: usize) -> i128 {
        let target = target as i128;
        let addend = addend as i128;
        let place = place as i128;

        match self {
            RelocationValueFormula::Absolute => target + addend,
            RelocationValueFormula::RelativeToPlace => target + addend - place,
        }
    }
}

/// Resolve the final address for an IFUNC resolver entry.
///
/// # Safety
/// The address must point to a valid IFUNC resolver function.
#[inline(always)]
pub(crate) unsafe fn resolve_ifunc(addr: RelocAddr) -> RelocAddr {
    let ifunc: fn() -> usize = unsafe { core::mem::transmute(addr.into_inner()) };
    RelocAddr::new(ifunc())
}

#[cfg(feature = "object")]
impl RelocSWord32 {
    #[inline]
    pub const fn to_ne_bytes(self) -> [u8; 4] {
        self.0.to_ne_bytes()
    }
}
