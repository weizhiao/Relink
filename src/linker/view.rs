use super::{request::VisibleModules, session::ResolveSession, storage::CommittedStorageView};

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

enum DependencyGraphSource<'a, K: Clone, D: 'static, M = ()> {
    Committed(CommittedStorageView<'a, K, D, M>),
    Overlay {
        committed: CommittedStorageView<'a, K, D, M>,
        local: &'a dyn DependencyGraphEntries<K>,
        visible: &'a dyn VisibleModules<K, D>,
    },
}

impl<'a, K: Clone, D: 'static, M> Copy for DependencyGraphSource<'a, K, D, M> {}

impl<'a, K: Clone, D: 'static, M> Clone for DependencyGraphSource<'a, K, D, M> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

/// Read-only dependency-graph view visible to one resolution pass.
pub struct DependencyGraphView<'a, K: Clone, D: 'static, M = ()> {
    source: DependencyGraphSource<'a, K, D, M>,
}

impl<'a, K: Clone, D: 'static, M> Copy for DependencyGraphView<'a, K, D, M> {}

impl<'a, K: Clone, D: 'static, M> Clone for DependencyGraphView<'a, K, D, M> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static, M> DependencyGraphView<'a, K, D, M>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn new_committed(committed: CommittedStorageView<'a, K, D, M>) -> Self {
        Self {
            source: DependencyGraphSource::Committed(committed),
        }
    }

    #[inline]
    pub(crate) fn new_overlay(
        committed: CommittedStorageView<'a, K, D, M>,
        local: &'a dyn DependencyGraphEntries<K>,
        visible: &'a dyn VisibleModules<K, D>,
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
