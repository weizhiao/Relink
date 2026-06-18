use super::{
    request::VisibleModules,
    storage::{CommittedStorage, KeyId, ModuleId},
};
use crate::{
    LinkerError, Result, arch::NativeArch, image::ModuleHandle, relocation::RelocationArch,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    vec::Vec,
};
use core::borrow::Borrow;

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
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.contains_key(key)
    }

    /// Returns whether the context contains the committed module `id`.
    #[inline]
    pub fn contains_module(&self, id: ModuleId) -> bool {
        self.committed.contains_module(id)
    }

    /// Returns the interned id for a known key.
    #[inline]
    pub fn key_id<Q>(&self, key: &Q) -> Option<KeyId>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed.key_id(key)
    }

    /// Returns the key associated with an interned id.
    #[inline]
    pub fn key(&self, id: KeyId) -> Option<&K> {
        self.committed.key(id)
    }

    /// Returns the committed module id that `id` resolves to.
    #[inline]
    pub fn module_id(&self, id: KeyId) -> Option<ModuleId> {
        self.committed.module_id(id)
    }

    /// Returns the representative key associated with a committed module id.
    #[inline]
    pub fn module_key(&self, id: ModuleId) -> Option<&K> {
        let key_id = self.committed.entry_key_id(id)?;
        self.committed.key(key_id)
    }

    /// Returns the retained module handle associated with a committed module id.
    #[inline]
    pub fn get(&self, id: ModuleId) -> Option<&ModuleHandle<Arch>> {
        self.committed.get(id)
    }

    /// Returns a module by this context's key id, falling back to an external
    /// visible module set when the id only resolves to an interned key.
    #[inline]
    pub(crate) fn visible_module<V, Q>(
        &self,
        visible_modules: &V,
        id: KeyId,
    ) -> Option<ModuleHandle<Arch>>
    where
        K: Borrow<Q>,
        Q: ?Sized,
        V: VisibleModules<K, Arch, Q>,
    {
        self.committed.get_by_key(id).cloned().or_else(|| {
            let key = self.committed.key(id)?;
            visible_modules.module(key.borrow())
        })
    }

    /// Returns a module by key, accepting aliases from an external visible
    /// module set before falling back to the canonical visible module.
    #[inline]
    pub(crate) fn visible_module_by_key<V, Q>(
        &self,
        visible_modules: &V,
        key: &Q,
    ) -> Option<ModuleHandle<Arch>>
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q>,
    {
        self.committed
            .key_id(key)
            .and_then(|id| self.visible_module(visible_modules, id))
            .or_else(|| {
                let key = visible_modules.visible_key(key)?;
                self.committed
                    .key_id::<K>(&key)
                    .and_then(|id| self.visible_module(visible_modules, id))
                    .or_else(|| visible_modules.module(key.borrow()))
            })
    }

    /// Returns direct dependency key ids for a committed module.
    #[inline]
    pub fn direct_deps(&self, id: ModuleId) -> Option<&[KeyId]> {
        self.committed.direct_deps(id)
    }

    /// Iterates committed modules in load order.
    #[inline]
    pub fn load_order(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.committed.load_order()
    }

    /// Returns immutable user metadata for a committed module.
    #[inline]
    pub fn meta(&self, id: ModuleId) -> Option<&M> {
        self.committed.meta(id)
    }

    /// Returns mutable user metadata for a committed module.
    #[inline]
    pub fn meta_mut(&mut self, id: ModuleId) -> Option<&mut M> {
        self.committed.meta_mut(id)
    }

    /// Inserts an already retained module with default metadata.
    pub fn insert<R>(&mut self, key: K, module: R, direct_deps: Box<[K]>) -> Result<ModuleId>
    where
        M: Default,
        R: Into<ModuleHandle<Arch>>,
    {
        self.insert_with_meta(key, module, direct_deps, M::default())
    }

    /// Inserts an already retained module with explicit metadata.
    pub fn insert_with_meta<R>(
        &mut self,
        key: K,
        module: R,
        direct_deps: Box<[K]>,
        meta: M,
    ) -> Result<ModuleId>
    where
        R: Into<ModuleHandle<Arch>>,
    {
        if self.committed.contains_key(&key) {
            return Err(LinkerError::context("duplicate linked module key").into());
        }

        let id = self.committed.intern_key(key);
        let direct_deps = direct_deps
            .into_vec()
            .into_iter()
            .map(|key| self.committed.intern_key(key))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(self
            .committed
            .insert_new(id, module.into(), direct_deps, meta))
    }

    /// Adds an alternate key for an already committed module.
    pub fn add_alias<Q>(&mut self, canonical: &Q, alias: K) -> Result<ModuleId>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let Some(canonical_key_id) = self.committed.key_id(canonical) else {
            return Err(LinkerError::context("canonical linked module key is unknown").into());
        };
        let Some(module_id) = self.committed.module_id(canonical_key_id) else {
            return Err(LinkerError::context("canonical linked module is not committed").into());
        };

        if self
            .committed
            .key_id::<K>(&alias)
            .and_then(|id| self.committed.module_id(id))
            .is_some_and(|id| id != module_id)
        {
            return Err(
                LinkerError::context("alias linked module key is already committed").into(),
            );
        }

        self.committed.add_alias(module_id, alias);
        Ok(module_id)
    }

    /// Removes a committed module and returns its handle, dependencies, and metadata.
    #[inline]
    pub fn remove(&mut self, id: ModuleId) -> Option<(ModuleHandle<Arch>, Box<[KeyId]>, M)> {
        self.committed.remove(id)
    }

    /// Returns the breadth-first dependency scope rooted at `root`.
    pub fn dependency_scope(&self, root: ModuleId) -> Result<Vec<ModuleId>> {
        if !self.committed.contains_module(root) {
            return Err(LinkerError::context("dependency scope root is not committed").into());
        }

        let mut scope = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(root);
        queue.push_back(root);

        while let Some(id) = queue.pop_front() {
            let Some(direct_deps) = self.committed.direct_deps(id) else {
                return Err(
                    LinkerError::context("dependency scope module is not committed").into(),
                );
            };

            scope.push(id);
            for dep in direct_deps.iter().copied() {
                let Some(dep) = self.committed.module_id(dep) else {
                    return Err(LinkerError::context(
                        "dependency scope dependency is not committed",
                    )
                    .into());
                };
                if visited.insert(dep) {
                    queue.push_back(dep);
                }
            }
        }

        Ok(scope)
    }

    /// Extends this context with modules from another context.
    pub fn extend(&mut self, other: &LinkContext<K, D, M, Arch>) -> Result<()>
    where
        M: Clone,
    {
        for id in other.load_order() {
            let key = other
                .module_key(id)
                .expect("load_order entries must resolve to module keys");
            if self.committed.contains_key(key) {
                continue;
            }

            let module = other
                .get(id)
                .cloned()
                .expect("load_order entries must resolve to committed modules");
            let direct_deps = other
                .direct_deps(id)
                .expect("load_order entries must resolve to committed dependencies")
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
            self.insert_with_meta(key.clone(), module, direct_deps, meta)?;
        }

        for (alias_id, target_module) in other.committed.aliases() {
            let alias = other
                .key(alias_id)
                .expect("alias id must resolve to an interned key");
            let canonical = other
                .module_key(target_module)
                .expect("alias target id must resolve to a module key");
            if self.committed.contains_key(alias) {
                continue;
            }
            self.add_alias(canonical, alias.clone())?;
        }
        Ok(())
    }

    /// Creates a detached clone of the committed context state.
    pub fn snapshot(&self) -> Self
    where
        M: Clone,
    {
        Self {
            committed: self.committed.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LinkContext;
    use crate::{arch::NativeArch, image::SyntheticModule};
    use alloc::{boxed::Box, string::String};

    #[test]
    fn snapshot_clones_committed_state_without_rebuilding() {
        let mut context = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let root = context
            .insert_with_meta("root", SyntheticModule::empty("root"), Box::new(["dep"]), 7)
            .expect("failed to insert root module");
        let dep = context
            .key_id(&"dep")
            .expect("dependency key should be interned");

        let snapshot = context.snapshot();
        context.remove(root);

        assert!(!context.contains_module(root));
        assert!(snapshot.contains_module(root));
        assert!(snapshot.module_id(dep).is_none());
        assert_eq!(snapshot.module_key(root), Some(&"root"));
        assert_eq!(snapshot.key(dep), Some(&"dep"));
        assert_eq!(snapshot.direct_deps(root), Some(&[dep][..]));
        assert_eq!(snapshot.meta(root), Some(&7));
    }

    #[test]
    fn alias_resolves_preinterned_dependency_edges_without_rewriting() {
        let mut context = LinkContext::<String, (), usize, NativeArch>::new();
        let root = context
            .insert_with_meta(
                String::from("root"),
                SyntheticModule::empty("root"),
                Box::new([String::from("alias")]),
                1,
            )
            .expect("failed to insert root module");
        let alias_id = context
            .key_id("alias")
            .expect("dependency key should be interned before aliasing");

        let canonical = context
            .insert_with_meta(
                String::from("canonical"),
                SyntheticModule::empty("canonical"),
                Box::new([]),
                2,
            )
            .expect("failed to insert canonical module");
        let resolved = context
            .add_alias("canonical", String::from("alias"))
            .expect("failed to add alias");

        assert_eq!(resolved, canonical);
        assert!(context.module_id(alias_id).is_some());
        assert_eq!(context.key_id("alias"), Some(alias_id));
        assert_eq!(context.module_id(alias_id), Some(canonical));
        assert_eq!(context.direct_deps(root), Some(&[alias_id][..]));
        assert_eq!(
            context
                .dependency_scope(root)
                .expect("dependency scope should resolve")
                .as_slice(),
            &[root, canonical]
        );
    }

    #[test]
    fn extend_preserves_aliases_without_rewriting_dependency_edges() {
        let mut source = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let root = source
            .insert_with_meta(
                "root",
                SyntheticModule::empty("root"),
                Box::new(["alias"]),
                1,
            )
            .expect("failed to insert root module");
        let alias = source
            .key_id(&"alias")
            .expect("dependency key should be interned before aliasing");
        let canonical = source
            .insert_with_meta(
                "canonical",
                SyntheticModule::empty("canonical"),
                Box::new([]),
                2,
            )
            .expect("failed to insert canonical module");
        source
            .add_alias(&"canonical", "alias")
            .expect("failed to add alias");

        let mut target = LinkContext::<&'static str, (), usize, NativeArch>::new();
        target.extend(&source).expect("failed to extend context");
        let target_root = target
            .key_id(&"root")
            .and_then(|id| target.module_id(id))
            .expect("root module should be copied");
        let target_alias = target.key_id(&"alias").expect("alias key should be copied");
        let target_canonical = target
            .key_id(&"canonical")
            .and_then(|id| target.module_id(id))
            .expect("canonical key should be copied");

        assert_eq!(source.direct_deps(root), Some(&[alias][..]));
        assert_eq!(
            source
                .dependency_scope(root)
                .expect("source scope should resolve")
                .as_slice(),
            &[root, canonical]
        );
        assert_eq!(target.direct_deps(target_root), Some(&[target_alias][..]));
        assert_eq!(target.module_id(target_alias), Some(target_canonical));
        assert_eq!(
            target
                .dependency_scope(target_root)
                .expect("target scope should resolve")
                .as_slice(),
            &[target_root, target_canonical]
        );
    }
}
