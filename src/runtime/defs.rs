use crate::{
    Error, Result,
    sync::{AtomicUsize, Ordering},
};

static NEXT_DOMAIN_ID: AtomicUsize = AtomicUsize::new(1);

/// Identity of one mutually compatible runtime environment.
///
/// Modules in the same domain may directly exchange runtime addresses. A domain
/// therefore covers the target address space, code execution, TLS namespace,
/// and other runtime services involved in relocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DomainId(usize);

impl DomainId {
    /// Domain of the current native process.
    pub const PROCESS: Self = Self(0);

    /// Creates an identity for an independent runtime environment.
    pub fn new() -> Self {
        Self(
            NEXT_DOMAIN_ID
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .expect("runtime domain identity space is exhausted"),
        )
    }

    #[inline]
    pub(crate) fn ensure(self, actual: Self) -> Result<()> {
        if self == actual {
            Ok(())
        } else {
            Err(Error::DomainMismatch {
                expected: self,
                actual,
            })
        }
    }
}

impl core::fmt::Display for DomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}
