#[cfg(not(feature = "portable-atomic"))]
mod inner {
    pub(crate) use alloc::sync::{Arc, Weak};
    pub(crate) use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
}

#[cfg(feature = "portable-atomic")]
mod inner {
    pub(crate) use portable_atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    pub(crate) use portable_atomic_util::{Arc, Weak};
}

pub(crate) use inner::*;

pub(crate) struct OnceCell<T>(spin::Once<T>);

impl<T> OnceCell<T> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self(spin::Once::new())
    }

    #[inline]
    pub(crate) fn get(&self) -> Option<&T> {
        self.0.get()
    }

    #[inline]
    pub(crate) fn get_or_init(&self, init: impl FnOnce() -> T) -> &T {
        self.0.call_once(init)
    }

    pub(crate) fn set(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        self.0
            .call_once(|| value.take().expect("once-cell value must be available"));
        match value {
            None => Ok(()),
            Some(value) => Err(value),
        }
    }
}

macro_rules! arc_unsize {
    ($arc:expr => $target:ty) => {{
        let ptr = $crate::sync::Arc::into_raw($arc);
        let ptr: *const $target = ptr;
        // SAFETY: The coercion above preserves the allocation address and only
        // adds metadata accepted by the compiler. This reconstructs exactly the
        // one Arc consumed by into_raw.
        unsafe { $crate::sync::Arc::<$target>::from_raw(ptr) }
    }};
}

pub(crate) use arc_unsize;

macro_rules! arc_downgrade_unsize {
    ($arc:expr => $target:ty) => {{
        let arc: &$crate::sync::Arc<_> = $arc;
        // SAFETY: Copy the handle without incrementing its strong count. The
        // borrowed original keeps the allocation alive throughout this block.
        // arc_unsize only transfers the copied handle through raw pointers;
        // ManuallyDrop prevents it from releasing the original's strong count.
        let borrowed = core::mem::ManuallyDrop::new($crate::sync::arc_unsize!(
            unsafe { core::ptr::read(arc) } => $target
        ));
        $crate::sync::Arc::downgrade(&borrowed)
    }};
}

pub(crate) use arc_downgrade_unsize;
