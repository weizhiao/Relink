use super::storage::{CommittedEntry, CommittedStorage, KeyId};
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
    /// Creates an empty link context.
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
    /// Returns whether no modules have been committed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    /// Returns whether the context contains a module with `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.committed.contains_key(key)
    }

    /// Returns whether the context contains an entry with `id`.
    #[inline]
    pub fn contains(&self, id: KeyId) -> bool {
        self.committed.contains(id)
    }

    /// Returns the interned id for a committed key.
    #[inline]
    pub fn key_id(&self, key: &K) -> Option<KeyId> {
        self.committed.key_id(key)
    }

    /// Returns the key associated with an interned id.
    #[inline]
    pub fn key(&self, id: KeyId) -> Option<&K> {
        self.committed.key(id)
    }

    /// Returns the loaded module associated with an interned id.
    #[inline]
    pub fn get(&self, id: KeyId) -> Option<&LoadedCore<D, Arch>> {
        self.committed.get(id)
    }

    /// Returns direct dependency ids for a committed module.
    #[inline]
    pub fn direct_deps(&self, id: KeyId) -> Option<&[KeyId]> {
        self.committed.direct_deps(id)
    }

    /// Iterates committed modules in load order.
    #[inline]
    pub fn load_order(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.committed.load_order()
    }

    /// Returns immutable user metadata for a committed module.
    #[inline]
    pub fn meta(&self, id: KeyId) -> Option<&M> {
        self.committed.meta(id)
    }

    /// Returns mutable user metadata for a committed module.
    #[inline]
    pub fn meta_mut(&mut self, id: KeyId) -> Option<&mut M> {
        self.committed.meta_mut(id)
    }

    /// Inserts an already loaded module with default metadata.
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

    /// Inserts an already loaded module with explicit metadata.
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

    /// Removes a committed module and returns its image, dependencies, and metadata.
    #[inline]
    pub fn remove(&mut self, id: KeyId) -> Option<(LoadedCore<D, Arch>, Box<[KeyId]>, M)> {
        self.committed.remove(id)
    }

    /// Returns the breadth-first dependency scope rooted at `root`.
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

    /// Returns retained loaded modules in the dependency scope rooted at `root`.
    pub fn dependency_modules(&self, root: KeyId) -> Arc<[LoadedCore<D, Arch>]> {
        let scope = self
            .dependency_scope(root)
            .into_iter()
            .filter_map(|id| self.committed.get(id).cloned())
            .collect::<Vec<_>>();
        Arc::from(scope)
    }

    /// Extends this context with modules from another context.
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

    /// Creates a detached clone of the committed context state.
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
