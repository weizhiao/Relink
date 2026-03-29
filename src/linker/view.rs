use super::storage::{CommittedStorageView, StagedStorageView};

/// Read-only view of the loaded modules currently visible to a load session.
///
/// The view can represent the stable contents of a [`LinkContext`] plus any
/// newly linked modules that were produced earlier in the current `load()`
/// call.
pub struct LinkContextView<'a, K, D: 'static> {
    committed: CommittedStorageView<'a, K, D>,
    staged: Option<StagedStorageView<'a, K, D>>,
}

impl<'a, K, D: 'static> Copy for LinkContextView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for LinkContextView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> LinkContextView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn new(
        committed: CommittedStorageView<'a, K, D>,
        staged: Option<StagedStorageView<'a, K, D>>,
    ) -> Self {
        Self { committed, staged }
    }

    /// Returns whether the key is already present in the visible linked modules.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.staged
            .as_ref()
            .is_some_and(|staged| staged.contains_key(key))
            || self.committed.contains_key(key)
    }

    /// Returns the direct dependency keys recorded for a module.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.staged
            .as_ref()
            .and_then(|staged| staged.direct_deps(key))
            .or_else(|| self.committed.direct_deps(key))
    }

    /// Returns the visible module for a key.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&'a crate::image::LoadedCore<D>> {
        self.staged
            .as_ref()
            .and_then(|staged| staged.get(key))
            .or_else(|| self.committed.get(key))
    }
}
