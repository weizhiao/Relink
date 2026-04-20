use super::{session::ResolveSession, storage::CommittedStorageView};

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

enum DependencyGraphSource<'a, K, D: 'static> {
    Committed(CommittedStorageView<'a, K, D>),
    Overlay {
        committed: CommittedStorageView<'a, K, D>,
        local: &'a dyn DependencyGraphEntries<K>,
    },
}

impl<'a, K, D: 'static> Copy for DependencyGraphSource<'a, K, D> {}

impl<'a, K, D: 'static> Clone for DependencyGraphSource<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

/// Read-only dependency-graph view visible to one resolution pass.
pub struct DependencyGraphView<'a, K, D: 'static> {
    source: DependencyGraphSource<'a, K, D>,
}

impl<'a, K, D: 'static> Copy for DependencyGraphView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for DependencyGraphView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> DependencyGraphView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn new_committed(committed: CommittedStorageView<'a, K, D>) -> Self {
        Self {
            source: DependencyGraphSource::Committed(committed),
        }
    }

    #[inline]
    pub(crate) fn new_overlay(
        committed: CommittedStorageView<'a, K, D>,
        local: &'a dyn DependencyGraphEntries<K>,
    ) -> Self {
        Self {
            source: DependencyGraphSource::Overlay { committed, local },
        }
    }

    /// Returns whether the key is already present in the visible dependency graph.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        match self.source {
            DependencyGraphSource::Committed(committed) => committed.contains_key(key),
            DependencyGraphSource::Overlay { committed, local } => {
                local.contains_key(key) || committed.contains_key(key)
            }
        }
    }

    /// Returns the direct dependency keys recorded for a module.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        match self.source {
            DependencyGraphSource::Committed(committed) => committed.direct_deps(key),
            DependencyGraphSource::Overlay { committed, local } => local
                .direct_deps(key)
                .or_else(|| committed.direct_deps(key)),
        }
    }
}
