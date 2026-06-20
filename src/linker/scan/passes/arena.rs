use super::{LinkPassPlan, ReorderAccess};
use crate::{
    linker::scan::{ArenaDescriptor, ArenaId, ArenaUsage},
    relocation::RelocationArch,
    tls::TlsResolver,
};
use core::marker::PhantomData;

/// An arena handle created through a reorder-capable pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Arena<'plan> {
    id: ArenaId,
    marker: PhantomData<fn(&'plan ())>,
}

impl<'plan> Arena<'plan> {
    #[inline]
    pub(super) const fn new(id: ArenaId) -> Self {
        Self {
            id,
            marker: PhantomData,
        }
    }

    #[inline]
    pub(in crate::linker) const fn id(self) -> ArenaId {
        self.id
    }
}

impl<'scope> Arena<'scope> {
    /// Returns this arena's descriptor through `plan`.
    #[inline]
    pub fn descriptor<'borrow, K, S, Arch, Tls>(
        self,
        plan: &'borrow LinkPassPlan<'scope, K, S, Arch, Tls>,
    ) -> &'borrow ArenaDescriptor
    where
        K: Clone + Ord,
        S: ReorderAccess,
        Arch: RelocationArch,
        Tls: TlsResolver,
    {
        plan.plan.memory_layout().arena(self.id)
    }

    /// Returns this arena's derived usage summary through `plan`.
    #[inline]
    pub fn usage<K, S, Arch, Tls>(self, plan: &LinkPassPlan<'scope, K, S, Arch, Tls>) -> ArenaUsage
    where
        K: Clone + Ord,
        S: ReorderAccess,
        Arch: RelocationArch,
        Tls: TlsResolver,
    {
        plan.plan.memory_layout().usage(self.id)
    }
}
