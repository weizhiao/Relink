#[cfg(not(feature = "portable-atomic"))]
mod inner {
    pub(crate) use alloc::sync::{Arc, Weak};
    #[cfg(feature = "tls")]
    pub(crate) use core::sync::atomic::AtomicUsize;
    pub(crate) use core::sync::atomic::{AtomicBool, Ordering};
}

#[cfg(feature = "portable-atomic")]
mod inner {
    #[cfg(feature = "tls")]
    pub(crate) use portable_atomic::AtomicUsize;
    pub(crate) use portable_atomic::{AtomicBool, Ordering};
    pub(crate) use portable_atomic_util::{Arc, Weak};
}

pub(crate) use inner::*;
