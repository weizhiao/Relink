use super::{
    storage::{CommittedEntry, CommittedStorage, KeyId},
    view::DependencyGraphView,
};
use crate::{LinkerError, Result, arch::NativeArch, image::LoadedCore, relocation::RelocationArch};
use alloc::{
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    sync::Arc,
    vec::Vec,
};

/// A reusable local module repository and committed dependency graph.
///
/// The context is a single relocation-domain module repository and committed
/// dependency graph.
pub struct LinkContext<K, D: 'static, M = (), Arch: RelocationArch = NativeArch> {
    pub(super) committed: CommittedStorage<K, D, M, Arch>,
}

impl<K, D: 'static, M, Arch> Default for LinkContext<K, D, M, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, D: 'static, M, Arch> LinkContext<K, D, M, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub fn new() -> Self {
        Self {
            committed: CommittedStorage::new(),
        }
    }
}

impl<K, D: 'static, M, Arch> LinkContext<K, D, M, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.committed.contains_key(key)
    }

    #[inline]
    pub fn contains(&self, id: KeyId) -> bool {
        self.committed.contains(id)
    }

    #[inline]
    pub fn key_id(&self, key: &K) -> Option<KeyId> {
        self.committed.key_id(key)
    }

    #[inline]
    pub fn key(&self, id: KeyId) -> Option<&K> {
        self.committed.key(id)
    }

    #[inline]
    pub fn get(&self, id: KeyId) -> Option<&LoadedCore<D, Arch>> {
        self.committed.get(id)
    }

    #[inline]
    pub fn direct_deps(&self, id: KeyId) -> Option<&[KeyId]> {
        self.committed.direct_deps(id)
    }

    #[inline]
    pub fn load_order(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.committed.load_order()
    }

    #[inline]
    pub fn view(&self) -> DependencyGraphView<'_, K, D, M, Arch> {
        DependencyGraphView::new_committed(self.committed.view())
    }

    #[inline]
    pub fn meta(&self, id: KeyId) -> Option<&M> {
        self.committed.meta(id)
    }

    #[inline]
    pub fn meta_mut(&mut self, id: KeyId) -> Option<&mut M> {
        self.committed.meta_mut(id)
    }

    pub fn insert(
        &mut self,
        key: K,
        module: LoadedCore<D, Arch>,
        direct_deps: Box<[K]>,
    ) -> Result<KeyId>
    where
        M: Default,
    {
        self.insert_with_meta(key, module, direct_deps, M::default())
    }

    pub fn insert_with_meta(
        &mut self,
        key: K,
        module: LoadedCore<D, Arch>,
        direct_deps: Box<[K]>,
        meta: M,
    ) -> Result<KeyId> {
        if self.committed.contains_key(&key) {
            return Err(LinkerError::context("duplicate linked module key").into());
        }

        Ok(self
            .committed
            .insert_new(key, CommittedEntry::new(module, direct_deps, meta)))
    }

    #[inline]
    pub fn remove(&mut self, id: KeyId) -> Option<(LoadedCore<D, Arch>, Box<[KeyId]>, M)> {
        self.committed.remove(id)
    }

    pub fn dependency_scope(&self, root: KeyId) -> Vec<KeyId> {
        if !self.committed.contains(root) {
            return Vec::new();
        }

        let mut scope = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(root);
        queue.push_back(root);

        while let Some(id) = queue.pop_front() {
            let Some(direct_deps) = self.committed.direct_deps(id) else {
                continue;
            };

            scope.push(id);
            for dep in direct_deps.iter().copied() {
                if visited.insert(dep) {
                    queue.push_back(dep);
                }
            }
        }

        scope
    }

    pub fn dependency_modules(&self, root: KeyId) -> Arc<[LoadedCore<D, Arch>]> {
        let scope = self
            .dependency_scope(root)
            .into_iter()
            .filter_map(|id| self.committed.get(id).cloned())
            .collect::<Vec<_>>();
        Arc::from(scope)
    }

    pub fn extend(&mut self, other: &LinkContext<K, D, M, Arch>) -> Result<()>
    where
        M: Clone,
    {
        for id in other.load_order() {
            let key = other
                .key(id)
                .expect("load_order entries must resolve to interned keys");
            if self.committed.contains_key(key) {
                continue;
            }

            let module = other
                .get(id)
                .cloned()
                .expect("load_order entries must resolve to committed modules");
            let direct_deps = other
                .direct_deps(id)
                .unwrap_or(&[])
                .iter()
                .map(|dep| {
                    other
                        .key(*dep)
                        .expect("direct dependency ids must resolve to interned keys")
                        .clone()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let meta = other
                .meta(id)
                .cloned()
                .expect("load_order entries must resolve to committed metadata");
            self.committed
                .insert_new(key.clone(), CommittedEntry::new(module, direct_deps, meta));
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Self
    where
        M: Clone,
    {
        let mut snapshot = Self::new();
        snapshot
            .extend(self)
            .expect("link context snapshot must not fail");
        snapshot
    }
}
