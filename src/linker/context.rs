use super::{
    storage::{CommittedEntry, CommittedStorage},
    view::DependencyGraphView,
};
use crate::{LinkerError, Result, image::LoadedCore};
use alloc::{
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::borrow::Borrow;

/// A reusable local module repository and committed dependency graph.
///
/// This context stores only committed modules. Discovery, planning, relocation,
/// and commit orchestration are owned by [`super::Linker`].
pub struct LinkContext<K, D: 'static, M = ()> {
    pub(super) committed: CommittedStorage<K, D, M>,
}

impl<K, D: 'static, M> Default for LinkContext<K, D, M> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, D: 'static, M> LinkContext<K, D, M> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            committed: CommittedStorage::new(),
        }
    }
}

impl<K, D: 'static, M> LinkContext<K, D, M>
where
    K: Clone + Ord,
{
    /// Returns whether the context is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    /// Returns whether a committed module exists for `key`.
    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.contains_key(key)
    }

    /// Returns the committed module for `key`.
    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&LoadedCore<D>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.get(key)
    }

    /// Returns the canonical committed key and module for `key`.
    #[inline]
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &LoadedCore<D>)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed
            .get_key_value(key)
            .map(|(key, entry)| (key, &entry.module))
    }

    /// Returns the committed direct dependencies recorded for `key`.
    #[inline]
    pub fn direct_deps<Q>(&self, key: &Q) -> Option<&[K]>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.view().direct_deps(key)
    }

    /// Returns the committed keys in load order.
    #[inline]
    pub fn load_order(&self) -> &[K] {
        self.committed.load_order()
    }

    /// Returns a read-only view over the current committed dependency graph.
    #[inline]
    pub fn view(&self) -> DependencyGraphView<'_, K, D, M> {
        DependencyGraphView::new_committed(self.committed.view())
    }

    /// Returns the metadata associated with a committed module.
    #[inline]
    pub fn meta<Q>(&self, key: &Q) -> Option<&M>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.entry(key).map(|entry| &entry.meta)
    }

    /// Returns mutable metadata associated with a committed module.
    #[inline]
    pub fn meta_mut<Q>(&mut self, key: &Q) -> Option<&mut M>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.entry_mut(key).map(|entry| &mut entry.meta)
    }

    /// Inserts an already-loaded module into the committed context.
    ///
    /// This is intended for callers that bootstrap a process-global context
    /// from externally discovered shared objects.
    pub fn insert(&mut self, key: K, module: LoadedCore<D>, direct_deps: Box<[K]>) -> Result<()>
    where
        M: Default,
    {
        self.insert_with_meta(key, module, direct_deps, M::default())
    }

    /// Inserts an already-loaded module with caller-managed metadata.
    pub fn insert_with_meta(
        &mut self,
        key: K,
        module: LoadedCore<D>,
        direct_deps: Box<[K]>,
        meta: M,
    ) -> Result<()> {
        if self.committed.contains_key(&key) {
            return Err(LinkerError::context("duplicate linked module key").into());
        }

        self.committed
            .insert_new(key, CommittedEntry::new(module, direct_deps, meta));
        Ok(())
    }

    /// Removes a committed module and returns its module, direct dependencies,
    /// and metadata.
    #[inline]
    pub fn remove<Q>(&mut self, key: &Q) -> Option<(LoadedCore<D>, Box<[K]>, M)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.remove(key).map(CommittedEntry::into_parts)
    }

    /// Builds the transitive dependency scope for `root` in breadth-first order.
    pub fn dependency_scope_keys(&self, root: &K) -> Vec<K> {
        if !self.committed.contains_key(root) {
            return Vec::new();
        }

        let mut scope = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(root.clone());
        queue.push_back(root.clone());

        while let Some(key) = queue.pop_front() {
            let Some(entry) = self.committed.entry(&key) else {
                continue;
            };
            scope.push(key);

            for dep in &entry.direct_deps {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }

        scope
    }

    /// Builds the transitive dependency scope for `root` in breadth-first order.
    pub fn dependency_scope(&self, root: &K) -> Arc<[LoadedCore<D>]> {
        let scope = self
            .dependency_scope_keys(root)
            .into_iter()
            .filter_map(|key| self.committed.get(&key).cloned())
            .collect::<Vec<_>>();
        Arc::from(scope)
    }

    /// Copies committed modules from another context into this one in source
    /// load order.
    pub fn extend(&mut self, other: &LinkContext<K, D, M>) -> Result<()>
    where
        M: Clone,
    {
        for key in other.load_order() {
            if self.committed.contains_key(key) {
                continue;
            }

            let module = other
                .get(key)
                .cloned()
                .expect("load_order entries must resolve to committed modules");
            let direct_deps = other
                .direct_deps(key)
                .unwrap_or(&[])
                .to_vec()
                .into_boxed_slice();
            let meta = other
                .meta(key)
                .cloned()
                .expect("load_order entries must resolve to committed metadata");
            self.committed
                .insert_new(key.clone(), CommittedEntry::new(module, direct_deps, meta));
        }
        Ok(())
    }

    /// Creates a committed-graph snapshot that can be used as an isolated load
    /// session and later merged back into the source context.
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
