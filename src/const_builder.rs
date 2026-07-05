use core::{mem::MaybeUninit, ptr};

/// Field storage for const builders that must move values out of `self`
/// without dropping the original aggregate.
pub(crate) struct NoDrop<T>(MaybeUninit<T>);

impl<T> NoDrop<T> {
    #[inline]
    pub(crate) const fn new(value: T) -> Self {
        Self(MaybeUninit::new(value))
    }

    #[inline]
    pub(crate) const unsafe fn read(src: *const T) -> Self {
        // SAFETY: The caller guarantees that `src` points to a valid,
        // initialized `T` that will not be dropped again from its original
        // location.
        Self::new(unsafe { ptr::read(src) })
    }

    #[inline]
    pub(crate) const fn into_inner(self) -> T {
        // SAFETY: `NoDrop` is only constructed from fully initialized values.
        // The wrapper suppresses automatic drop until a const builder decides
        // whether to move the field into the next value or discard it under a
        // `Copy` bound.
        unsafe { self.0.assume_init() }
    }
}
