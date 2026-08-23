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

#[cfg(test)]
mod tests {
    use super::*;

    trait Value: Send + Sync {
        fn value(&self) -> usize;
    }

    struct Concrete(usize);

    impl Value for Concrete {
        fn value(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn arc_unsize_preserves_allocation() {
        let concrete = Arc::new(Concrete(42));
        let ptr = Arc::as_ptr(&concrete).cast::<()>();
        let value = arc_unsize!(concrete.clone() => dyn Value);

        assert_eq!(Arc::as_ptr(&value).cast::<()>(), ptr);
        assert_eq!(Arc::strong_count(&concrete), 2);
        assert_eq!(value.value(), 42);

        drop(value);
        assert_eq!(Arc::strong_count(&concrete), 1);
    }

    #[test]
    fn once_cell_rejects_replacement() {
        let cell = OnceCell::new();
        assert_eq!(cell.set(1), Ok(()));
        assert_eq!(cell.set(2), Err(2));
        assert_eq!(cell.get(), Some(&1));
    }
}
