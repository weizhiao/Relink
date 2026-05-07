use super::{
    storage::{CommittedEntry, CommittedStorage},
    view::DependencyGraphView,
};
use crate::{
    LinkerError, Result,
    image::{LoadedCore, LoadedModule},
    relocation::RelocationArch,
};
use alloc::{
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::borrow::Borrow;

/// A reusable local module repository and committed dependency graph.
///
/// The context is heterogeneous: committed entries may be loaded for different
/// built-in architectures, while typed accessors let callers recover
/// `LoadedCore<D, Arch>` when they know the expected module architecture.
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
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.contains_key(key)
    }

    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&LoadedModule<D>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.get(key)
    }

    #[inline]
    pub fn get_typed<Q, Arch>(&self, key: &Q) -> Option<LoadedCore<D, Arch>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
        Arch: RelocationArch,
    {
        self.get(key)?.downcast::<Arch>()
    }

    #[inline]
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &LoadedModule<D>)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed
            .get_key_value(key)
            .map(|(key, entry)| (key, &entry.module))
    }

    #[inline]
    pub fn direct_deps<Q>(&self, key: &Q) -> Option<&[K]>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.view().direct_deps(key)
    }

    #[inline]
    pub fn load_order(&self) -> &[K] {
        self.committed.load_order()
    }

    #[inline]
    pub fn view(&self) -> DependencyGraphView<'_, K, D, M> {
        DependencyGraphView::new_committed(self.committed.view())
    }

    #[inline]
    pub fn meta<Q>(&self, key: &Q) -> Option<&M>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.entry(key).map(|entry| &entry.meta)
    }

    #[inline]
    pub fn meta_mut<Q>(&mut self, key: &Q) -> Option<&mut M>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.entry_mut(key).map(|entry| &mut entry.meta)
    }

    pub fn insert(&mut self, key: K, module: LoadedModule<D>, direct_deps: Box<[K]>) -> Result<()>
    where
        M: Default,
    {
        self.insert_with_meta(key, module, direct_deps, M::default())
    }

    pub fn insert_typed<Arch>(
        &mut self,
        key: K,
        module: LoadedCore<D, Arch>,
        direct_deps: Box<[K]>,
    ) -> Result<()>
    where
        M: Default,
        Arch: RelocationArch,
    {
        self.insert(key, LoadedModule::from(module), direct_deps)
    }

    pub fn insert_with_meta(
        &mut self,
        key: K,
        module: LoadedModule<D>,
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

    pub fn insert_typed_with_meta<Arch>(
        &mut self,
        key: K,
        module: LoadedCore<D, Arch>,
        direct_deps: Box<[K]>,
        meta: M,
    ) -> Result<()>
    where
        Arch: RelocationArch,
    {
        self.insert_with_meta(key, LoadedModule::from(module), direct_deps, meta)
    }

    #[inline]
    pub fn remove<Q>(&mut self, key: &Q) -> Option<(LoadedModule<D>, Box<[K]>, M)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.remove(key).map(CommittedEntry::into_parts)
    }

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

    pub fn dependency_scope(&self, root: &K) -> Arc<[LoadedModule<D>]> {
        let scope = self
            .dependency_scope_keys(root)
            .into_iter()
            .filter_map(|key| self.committed.get(&key).cloned())
            .collect::<Vec<_>>();
        Arc::from(scope)
    }

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
