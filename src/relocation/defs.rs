#[cfg(feature = "object")]
use crate::RelocReason;
use crate::os::VmAddr;

/// A wrapper type for raw values written into relocation slots.
///
/// Address-like relocation results use [`VmAddr`]; this type keeps plain
/// integer payloads distinct from unchecked writes.
#[must_use = "relocation arithmetic returns a new value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct RelocValue<T>(T);

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
pub(crate) unsafe fn resolve_ifunc(addr: VmAddr) -> VmAddr {
    let ifunc: fn() -> usize = unsafe { core::mem::transmute(addr.into_inner()) };
    VmAddr::new(ifunc())
}

#[cfg(feature = "object")]
impl VmAddr {
    #[inline]
    pub(crate) fn try_into_sword32(self) -> core::result::Result<RelocSWord32, RelocReason> {
        i32::try_from(self.into_inner() as isize)
            .map(RelocValue::new)
            .map_err(|_| RelocReason::IntConversionOutOfRange)
    }
}

#[cfg(feature = "object")]
impl RelocSWord32 {
    #[inline]
    pub const fn to_ne_bytes(self) -> [u8; 4] {
        self.0.to_ne_bytes()
    }
}
