use super::{
    request::VisibleModules,
    session::ResolveSession,
    storage::{CommittedStorageView, KeyId},
};
use crate::relocation::RelocationArch;
use alloc::vec::Vec;

pub(crate) trait DependencyGraphEntries {
    fn contains(&self, id: KeyId) -> bool;

    fn direct_deps(&self, id: KeyId) -> Option<&[KeyId]>;
}

impl<P> DependencyGraphEntries for ResolveSession<P> {
    #[inline]
    fn contains(&self, id: KeyId) -> bool {
        self.entries.contains_key(&id)
    }

    #[inline]
    fn direct_deps(&self, id: KeyId) -> Option<&[KeyId]> {
        self.entries.get(&id).and_then(|entry| entry.direct_deps())
    }
}

enum DependencyGraphSource<
    'a,
    K: Clone,
    D: 'static,
    M = (),
    Arch: RelocationArch = crate::arch::NativeArch,
> {
    Committed(CommittedStorageView<'a, K, D, M, Arch>),
    Overlay {
        committed: CommittedStorageView<'a, K, D, M, Arch>,
        local: &'a dyn DependencyGraphEntries,
        visible: &'a dyn VisibleModules<K, D, Arch>,
    },
}

impl<'a, K: Clone, D: 'static, M, Arch> Copy for DependencyGraphSource<'a, K, D, M, Arch> where
    Arch: RelocationArch
{
}

impl<'a, K: Clone, D: 'static, M, Arch> Clone for DependencyGraphSource<'a, K, D, M, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

/// Read-only dependency-graph view visible to one resolution pass.
pub struct DependencyGraphView<
    'a,
    K: Clone,
    D: 'static,
    M = (),
    Arch: RelocationArch = crate::arch::NativeArch,
> {
    source: DependencyGraphSource<'a, K, D, M, Arch>,
}

impl<'a, K: Clone, D: 'static, M, Arch> Copy for DependencyGraphView<'a, K, D, M, Arch> where
    Arch: RelocationArch
{
}

impl<'a, K: Clone, D: 'static, M, Arch> Clone for DependencyGraphView<'a, K, D, M, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static, M, Arch> DependencyGraphView<'a, K, D, M, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new_committed(committed: CommittedStorageView<'a, K, D, M, Arch>) -> Self {
        Self {
            source: DependencyGraphSource::Committed(committed),
        }
    }

    #[inline]
    pub(crate) fn new_overlay(
        committed: CommittedStorageView<'a, K, D, M, Arch>,
        local: &'a dyn DependencyGraphEntries,
        visible: &'a dyn VisibleModules<K, D, Arch>,
    ) -> Self {
        Self {
            source: DependencyGraphSource::Overlay {
                committed,
                local,
                visible,
            },
        }
    }

    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        match self.source {
            DependencyGraphSource::Committed(committed) => committed.contains_key(key),
            DependencyGraphSource::Overlay {
                committed,
                local,
                visible,
            } => {
                committed
                    .key_id(key)
                    .is_some_and(|id| local.contains(id) || committed.contains(id))
                    || visible.contains_key(key)
            }
        }
    }

    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<Vec<K>> {
        fn keys_for_deps<K, D: 'static, M, Arch>(
            committed: CommittedStorageView<'_, K, D, M, Arch>,
            deps: &[KeyId],
        ) -> Vec<K>
        where
            K: Clone + Ord,
            Arch: RelocationArch,
        {
            deps.iter()
                .map(|id| {
                    committed
                        .key(*id)
                        .expect("dependency id must resolve to an interned key")
                        .clone()
                })
                .collect()
        }

        match self.source {
            DependencyGraphSource::Committed(committed) => committed.direct_deps_key(key),
            DependencyGraphSource::Overlay {
                committed, local, ..
            } => {
                let id = committed.key_id(key)?;
                local
                    .direct_deps(id)
                    .map(|deps| keys_for_deps(committed, deps))
                    .or_else(|| {
                        committed
                            .direct_deps(id)
                            .map(|deps| keys_for_deps(committed, deps))
                    })
            }
        }
    }
}
