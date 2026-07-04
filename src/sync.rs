#[cfg(not(feature = "portable-atomic"))]
mod inner {
    pub(crate) use alloc::sync::{Arc, Weak};
    pub(crate) use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
}

#[cfg(feature = "portable-atomic")]
mod inner {
    pub(crate) use portable_atomic::{AtomicBool, AtomicUsize, Ordering};
    pub(crate) use portable_atomic_util::{Arc, Weak};
}

pub(crate) use inner::*;
