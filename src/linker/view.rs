use super::{request::VisibleModules, session::ResolveSession, storage::CommittedStorageView};
use crate::relocation::RelocationArch;

pub(crate) trait DependencyGraphEntries<K> {
    fn contains_key(&self, key: &K) -> bool;

    fn direct_deps(&self, key: &K) -> Option<&[K]>;
}

impl<K, P> DependencyGraphEntries<K> for ResolveSession<K, P>
where
    K: Ord,
{
    #[inline]
    fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    fn direct_deps(&self, key: &K) -> Option<&[K]> {
        self.entries.get(key).and_then(|entry| entry.direct_deps())
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
        local: &'a dyn DependencyGraphEntries<K>,
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
        local: &'a dyn DependencyGraphEntries<K>,
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
                local.contains_key(key) || committed.contains_key(key) || visible.contains_key(key)
            }
        }
    }

    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        match self.source {
            DependencyGraphSource::Committed(committed) => committed.direct_deps(key),
            DependencyGraphSource::Overlay {
                committed, local, ..
            } => local
                .direct_deps(key)
                .or_else(|| committed.direct_deps(key)),
        }
    }
}
