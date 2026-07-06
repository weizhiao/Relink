use super::storage::{
    CommittedStorage, ContextId, DepEdge, EntryState, KeyId, ModuleId, ModuleSlot,
};
use crate::{
    LinkContextError, LinkerError, Result, arch::NativeArch, image::ModuleHandle,
    relocation::RelocationArch, tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    vec::Vec,
};
use core::borrow::Borrow;

#[inline]
fn require_module<T>(id: ModuleId, state: EntryState<T>) -> Result<T> {
    state
        .present()
        .ok_or_else(|| LinkerError::context(LinkContextError::ModuleNotCommitted { id }).into())
}

#[inline]
fn dep_ids(context: ContextId, edge: DepEdge) -> (KeyId, ModuleId) {
    (
        KeyId::from_slot(context, edge.key()),
        ModuleId::from_slot(context, edge.module()),
    )
}

/// Owned direct dependency edges removed from a link context.
pub struct DirectDeps {
    context: ContextId,
    edges: Box<[DepEdge]>,
}

impl DirectDeps {
    #[inline]
    fn new(context: ContextId, edges: Box<[DepEdge]>) -> Self {
        Self { context, edges }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (KeyId, ModuleId)> + '_ {
        let context = self.context;
        self.edges
            .iter()
            .copied()
            .map(move |edge| dep_ids(context, edge))
    }

    #[inline]
    pub fn into_iter(self) -> impl Iterator<Item = (KeyId, ModuleId)> {
        let context = self.context;
        self.edges
            .into_vec()
            .into_iter()
            .map(move |edge| dep_ids(context, edge))
    }
}

fn copy_committed_module<K, D, M, Arch, Tls>(
    target: &mut LinkContext<K, D, M, Arch, Tls>,
    source: &LinkContext<K, D, M, Arch, Tls>,
    slot: ModuleSlot,
    copied: &mut BTreeSet<ModuleSlot>,
) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
    M: Clone,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    if !copied.insert(slot) {
        return Ok(());
    }

    let id = source.committed.make_module_id(slot);
    let module = require_module(id, source.committed.module(slot))?;
    for dep in module.direct_deps().iter().copied() {
        copy_committed_module(target, source, dep.module(), copied)?;
    }

    let entry_key = source.committed.key(module.entry_key());
    if target.committed.contains_key(entry_key) {
        return Ok(());
    }

    let direct_deps = module
        .direct_deps()
        .iter()
        .map(|dep| {
            let dep_key = target
                .committed
                .intern_key(source.committed.key(dep.key()).clone());
            let source_dep_id = source.committed.make_module_id(dep.module());
            let source_dep = require_module(source_dep_id, source.committed.module(dep.module()))?;
            let source_dep_key = source.committed.key(source_dep.entry_key());
            let module = target
                .committed
                .key_slot_for(source_dep_key)
                .and_then(|slot| target.committed.module_for_key(slot))
                .expect("copied dependency module must resolve in target context");
            Ok(DepEdge::new(dep_key, module))
        })
        .collect::<Result<Vec<_>>>()?
        .into_boxed_slice();
    let entry_slot = target.committed.intern_key(entry_key.clone());
    target.committed.insert(
        entry_slot,
        module.handle().clone(),
        direct_deps,
        module.meta().clone(),
    );
    Ok(())
}

/// A reusable local module repository and committed dependency graph.
///
/// The context is a single relocation-domain module repository and committed
/// dependency graph.
pub struct LinkContext<
    K,
    D: 'static,
    M = (),
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    pub(super) committed: CommittedStorage<K, D, M, Arch, Tls>,
}

impl<K, D: 'static, M, Arch, Tls> Default for LinkContext<K, D, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, D: 'static, M, Arch, Tls> LinkContext<K, D, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates an empty link context.
    #[inline]
    pub fn new() -> Self {
        Self {
            committed: CommittedStorage::new(ContextId::fresh()),
        }
    }

    /// Returns this context's runtime identity.
    #[inline]
    pub fn context_id(&self) -> ContextId {
        self.committed.context()
    }
}

impl<K, D: 'static, M, Arch, Tls> LinkContext<K, D, M, Arch, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
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
    pub fn contains_module(&self, id: ModuleId) -> Result<bool> {
        Ok(self
            .committed
            .contains_module(self.committed.module_slot(id)?))
    }

    /// Returns the interned id for a known key.
    #[inline]
    pub fn key_id<Q>(&self, key: &Q) -> Option<KeyId>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed
            .key_slot_for(key)
            .map(|slot| self.committed.make_key_id(slot))
    }

    /// Returns the key associated with an interned id.
    #[inline]
    pub fn key(&self, id: KeyId) -> Result<&K> {
        let slot = self.committed.key_slot(id)?;
        Ok(self.committed.key(slot))
    }

    /// Returns the committed module id that `id` resolves to.
    #[inline]
    pub fn module_id(&self, id: KeyId) -> Result<Option<ModuleId>> {
        let slot = self.committed.key_slot(id)?;
        Ok(self
            .committed
            .module_for_key(slot)
            .map(|slot| self.committed.make_module_id(slot)))
    }

    /// Returns the representative key associated with a committed module id.
    #[inline]
    pub fn module_key(&self, id: ModuleId) -> Result<&K> {
        let module_slot = self.committed.module_slot(id)?;
        let module = require_module(id, self.committed.module(module_slot))?;
        Ok(self.committed.key(module.entry_key()))
    }

    /// Returns the retained module handle associated with a committed module id.
    #[inline]
    pub fn get(&self, id: ModuleId) -> Result<&ModuleHandle<Arch, Tls>> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module(slot))?.handle())
    }

    /// Returns direct dependency keys and bound modules for a committed module.
    #[inline]
    pub fn direct_deps(
        &self,
        id: ModuleId,
    ) -> Result<impl Iterator<Item = (KeyId, ModuleId)> + '_> {
        let slot = self.committed.module_slot(id)?;
        let context = self.committed.context();
        Ok(require_module(id, self.committed.module(slot))?
            .direct_deps()
            .iter()
            .copied()
            .map(move |edge| dep_ids(context, edge)))
    }

    /// Iterates committed modules in load order.
    #[inline]
    pub fn load_order(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.committed
            .load_order()
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Returns immutable user metadata for a committed module.
    #[inline]
    pub fn meta(&self, id: ModuleId) -> Result<&M> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module(slot))?.meta())
    }

    /// Returns mutable user metadata for a committed module.
    #[inline]
    pub fn meta_mut(&mut self, id: ModuleId) -> Result<&mut M> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module_mut(slot))?.meta_mut())
    }

    /// Inserts an already retained module with default metadata.
    pub fn insert<R>(&mut self, key: K, module: R, direct_deps: Box<[K]>) -> Result<ModuleId>
    where
        M: Default,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.insert_with_meta(key, module, direct_deps, M::default())
    }

    /// Inserts or replaces an already retained module with explicit metadata.
    pub fn insert_with_meta<R>(
        &mut self,
        key: K,
        module: R,
        direct_deps: Box<[K]>,
        meta: M,
    ) -> Result<ModuleId>
    where
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        let slot = self.committed.intern_key(key);
        let direct_deps = direct_deps
            .into_vec()
            .into_iter()
            .map(|key| self.committed.intern_key(key))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let direct_deps = self.committed.resolve_dep_edges(direct_deps)?;
        Ok(self
            .committed
            .insert(slot, module.into(), direct_deps, meta))
    }

    /// Adds or replaces an alternate key for an already committed module.
    ///
    /// Returns the previous committed module id when `alias` used to resolve to
    /// a different module.
    pub fn add_alias(&mut self, module_id: ModuleId, alias: K) -> Result<Option<ModuleId>> {
        let module_slot = self.committed.module_slot(module_id)?;
        if !self.committed.contains_module(module_slot) {
            return Err(LinkerError::context(LinkContextError::ModuleNotCommitted {
                id: module_id,
            })
            .into());
        }

        Ok(self
            .committed
            .add_alias(module_slot, alias)
            .map(|slot| self.committed.make_module_id(slot)))
    }

    /// Removes a committed module and returns its handle, dependencies, and metadata.
    #[inline]
    pub fn remove(&mut self, id: ModuleId) -> Result<(ModuleHandle<Arch, Tls>, DirectDeps, M)> {
        let slot = self.committed.module_slot(id)?;
        let (module, direct_deps, meta) = require_module(id, self.committed.remove(slot))?;
        Ok((
            module,
            DirectDeps::new(self.committed.context(), direct_deps),
            meta,
        ))
    }

    /// Returns the breadth-first dependency scope rooted at `root`.
    pub fn dependency_scope(&self, root: ModuleId) -> Result<Vec<ModuleId>> {
        let root_slot = self.committed.module_slot(root)?;
        if !self.committed.contains_module(root_slot) {
            return Err(
                LinkerError::context(LinkContextError::ModuleNotCommitted { id: root }).into(),
            );
        }

        let mut scope = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(root_slot);
        queue.push_back(root_slot);

        while let Some(slot) = queue.pop_front() {
            let id = self.committed.make_module_id(slot);
            let module = require_module(id, self.committed.module(slot))?;

            scope.push(id);
            for dep in module.direct_deps().iter().copied() {
                let dep = dep.module();
                let dep_id = self.committed.make_module_id(dep);
                require_module(dep_id, self.committed.module(dep))?;
                if visited.insert(dep) {
                    queue.push_back(dep);
                }
            }
        }

        Ok(scope)
    }

    /// Extends this context with modules from another context.
    pub fn extend(&mut self, other: &LinkContext<K, D, M, Arch, Tls>) -> Result<()>
    where
        M: Clone,
    {
        let mut copied = BTreeSet::new();
        for slot in other.committed.load_order() {
            copy_committed_module(self, other, slot, &mut copied)?;
        }

        for (alias_slot, target_slot) in other.committed.aliases() {
            let alias = other.committed.key(alias_slot);
            let target_id = other.committed.make_module_id(target_slot);
            let canonical_slot =
                require_module(target_id, other.committed.module(target_slot))?.entry_key();
            let canonical = other.committed.key(canonical_slot);
            if self.committed.contains_key(alias) {
                continue;
            }
            let canonical_slot = self
                .committed
                .key_slot_for(canonical)
                .and_then(|slot| self.committed.module_for_key(slot))
                .expect("copied alias target must resolve to a committed module");
            let _ = self.committed.add_alias(canonical_slot, alias.clone());
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
    use crate::{
        arch::NativeArch,
        image::SyntheticModule,
        linker::{KeyId, ModuleId},
    };
    use alloc::{boxed::Box, string::String, vec::Vec};

    fn direct_deps<K: Clone + Ord>(
        context: &LinkContext<K, (), usize, NativeArch>,
        id: ModuleId,
    ) -> Vec<(KeyId, ModuleId)> {
        context
            .direct_deps(id)
            .expect("direct deps should resolve")
            .collect()
    }

    #[test]
    fn ids_do_not_cross_contexts() {
        let mut first = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let first_root = first
            .insert_with_meta("root", SyntheticModule::empty("first"), Box::new([]), 1)
            .expect("failed to insert first module");
        let first_key = first.key_id(&"root").expect("root key should be interned");

        let mut second = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let second_root = second
            .insert_with_meta("root", SyntheticModule::empty("second"), Box::new([]), 2)
            .expect("failed to insert second module");
        let second_key = second.key_id(&"root").expect("root key should be interned");

        assert_ne!(first.context_id(), second.context_id());
        assert_ne!(first_root, second_root);
        assert_ne!(first_key, second_key);
        assert!(second.contains_module(first_root).is_err());
        assert!(second.get(first_root).is_err());
        assert!(second.key(first_key).is_err());
        assert!(second.module_id(first_key).is_err());
        assert!(second.dependency_scope(first_root).is_err());
        assert!(second.contains_module(second_root).unwrap());
    }

    #[test]
    fn snapshot_clones_committed_state_without_rebuilding() {
        let mut context = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let dep_module = context
            .insert_with_meta("dep", SyntheticModule::empty("dep"), Box::new([]), 3)
            .expect("failed to insert dependency module");
        let dep = context
            .key_id(&"dep")
            .expect("dependency key should be interned");
        let root = context
            .insert_with_meta("root", SyntheticModule::empty("root"), Box::new(["dep"]), 7)
            .expect("failed to insert root module");

        let snapshot = context.snapshot();
        assert_eq!(context.context_id(), snapshot.context_id());
        context.remove(root).unwrap();

        assert!(!context.contains_module(root).unwrap());
        assert!(context.get(root).is_err());
        assert!(snapshot.contains_module(root).unwrap());
        assert_eq!(snapshot.module_id(dep).unwrap(), Some(dep_module));
        assert_eq!(snapshot.module_key(root).unwrap(), &"root");
        assert_eq!(snapshot.key(dep).unwrap(), &"dep");
        assert_eq!(direct_deps(&snapshot, root), [(dep, dep_module)]);
        assert_eq!(snapshot.meta(root).unwrap(), &7);
    }

    #[test]
    fn dependency_edges_keep_their_bound_module_when_alias_changes() {
        let mut context = LinkContext::<String, (), usize, NativeArch>::new();
        let canonical = context
            .insert_with_meta(
                String::from("canonical"),
                SyntheticModule::empty("canonical"),
                Box::new([]),
                2,
            )
            .expect("failed to insert canonical module");
        context
            .add_alias(canonical, String::from("alias"))
            .expect("failed to add alias");
        let alias_id = context
            .key_id("alias")
            .expect("dependency key should be interned before root insertion");
        let root = context
            .insert_with_meta(
                String::from("root"),
                SyntheticModule::empty("root"),
                Box::new([String::from("alias")]),
                1,
            )
            .expect("failed to insert root module");
        let replacement = context
            .insert_with_meta(
                String::from("replacement"),
                SyntheticModule::empty("replacement"),
                Box::new([]),
                3,
            )
            .expect("failed to insert replacement module");
        context
            .add_alias(replacement, String::from("alias"))
            .expect("failed to replace alias");

        assert!(context.module_id(alias_id).unwrap().is_some());
        assert_eq!(context.key_id("alias"), Some(alias_id));
        assert_eq!(context.module_id(alias_id).unwrap(), Some(replacement));
        assert_eq!(direct_deps(&context, root), [(alias_id, canonical)]);
        assert_eq!(
            context
                .dependency_scope(root)
                .expect("dependency scope should resolve")
                .as_slice(),
            &[root, canonical]
        );
    }

    #[test]
    fn add_alias_replaces_existing_target() {
        let mut context = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let first = context
            .insert_with_meta("first", SyntheticModule::empty("first"), Box::new([]), 1)
            .expect("failed to insert first module");
        let second = context
            .insert_with_meta("second", SyntheticModule::empty("second"), Box::new([]), 2)
            .expect("failed to insert second module");

        assert_eq!(
            context
                .add_alias(first, "alias")
                .expect("failed to add alias"),
            None
        );
        let alias = context.key_id(&"alias").expect("alias key should exist");
        assert_eq!(context.module_id(alias).unwrap(), Some(first));
        assert_eq!(
            context
                .add_alias(second, "alias")
                .expect("failed to replace alias"),
            Some(first)
        );
        assert_eq!(context.module_id(alias).unwrap(), Some(second));
        assert_eq!(
            context
                .add_alias(second, "alias")
                .expect("failed to keep alias"),
            None
        );
    }

    #[test]
    fn insert_with_meta_replaces_existing_key_in_place() {
        let mut context = LinkContext::<&'static str, (), usize, NativeArch>::new();
        context
            .insert_with_meta("old", SyntheticModule::empty("old"), Box::new([]), 0)
            .expect("failed to insert old dependency");
        let root = context
            .insert_with_meta(
                "root",
                SyntheticModule::empty("old-root"),
                Box::new(["old"]),
                1,
            )
            .expect("failed to insert root module");
        let root_key = context.key_id(&"root").expect("root key should exist");
        let new_dep_module = context
            .insert_with_meta("new", SyntheticModule::empty("new"), Box::new([]), 0)
            .expect("failed to insert new dependency");

        let replaced = context
            .insert_with_meta(
                "root",
                SyntheticModule::empty("new-root"),
                Box::new(["new"]),
                2,
            )
            .expect("failed to replace root module");
        let new_dep = context
            .key_id(&"new")
            .expect("new dependency should be interned");

        assert_eq!(replaced, root);
        assert_eq!(context.key_id(&"root"), Some(root_key));
        assert_eq!(context.module_id(root_key).unwrap(), Some(root));
        assert_eq!(context.module_key(root).unwrap(), &"root");
        assert_eq!(context.meta(root).unwrap(), &2);
        assert_eq!(direct_deps(&context, root), [(new_dep, new_dep_module)]);
    }

    #[test]
    fn insert_with_meta_replaces_alias_target_in_place() {
        let mut context = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let root = context
            .insert_with_meta("root", SyntheticModule::empty("root"), Box::new([]), 1)
            .expect("failed to insert root module");
        context
            .add_alias(root, "alias")
            .expect("failed to add alias");
        let alias = context.key_id(&"alias").expect("alias key should exist");
        let dep_module = context
            .insert_with_meta("dep", SyntheticModule::empty("dep"), Box::new([]), 0)
            .expect("failed to insert dependency");

        let replaced = context
            .insert_with_meta(
                "alias",
                SyntheticModule::empty("alias"),
                Box::new(["dep"]),
                2,
            )
            .expect("failed to replace alias target");
        let dep = context
            .key_id(&"dep")
            .expect("dependency should be interned");

        assert_eq!(replaced, root);
        assert_eq!(context.module_id(alias).unwrap(), Some(root));
        assert_eq!(context.module_key(root).unwrap(), &"root");
        assert_eq!(context.meta(root).unwrap(), &2);
        assert_eq!(direct_deps(&context, root), [(dep, dep_module)]);
    }

    #[test]
    fn extend_preserves_bound_dependency_modules() {
        let mut source = LinkContext::<&'static str, (), usize, NativeArch>::new();
        let canonical = source
            .insert_with_meta(
                "canonical",
                SyntheticModule::empty("canonical"),
                Box::new([]),
                2,
            )
            .expect("failed to insert canonical module");
        source
            .add_alias(canonical, "alias")
            .expect("failed to add alias");
        let alias = source
            .key_id(&"alias")
            .expect("dependency key should be interned before root insertion");
        let root = source
            .insert_with_meta(
                "root",
                SyntheticModule::empty("root"),
                Box::new(["alias"]),
                1,
            )
            .expect("failed to insert root module");
        let replacement = source
            .insert_with_meta(
                "replacement",
                SyntheticModule::empty("replacement"),
                Box::new([]),
                3,
            )
            .expect("failed to insert replacement module");
        source
            .add_alias(replacement, "alias")
            .expect("failed to replace alias");

        let mut target = LinkContext::<&'static str, (), usize, NativeArch>::new();
        target.extend(&source).expect("failed to extend context");
        let target_root = target
            .key_id(&"root")
            .and_then(|id| target.module_id(id).unwrap())
            .expect("root module should be copied");
        let target_alias = target.key_id(&"alias").expect("alias key should be copied");
        let target_canonical = target
            .key_id(&"canonical")
            .and_then(|id| target.module_id(id).unwrap())
            .expect("canonical key should be copied");
        let target_replacement = target
            .key_id(&"replacement")
            .and_then(|id| target.module_id(id).unwrap())
            .expect("replacement key should be copied");

        assert_eq!(direct_deps(&source, root), [(alias, canonical)]);
        assert_eq!(
            source
                .dependency_scope(root)
                .expect("source scope should resolve")
                .as_slice(),
            &[root, canonical]
        );
        assert_eq!(
            direct_deps(&target, target_root),
            [(target_alias, target_canonical)]
        );
        assert_eq!(
            target.module_id(target_alias).unwrap(),
            Some(target_replacement)
        );
        assert_eq!(
            target
                .dependency_scope(target_root)
                .expect("target scope should resolve")
                .as_slice(),
            &[target_root, target_canonical]
        );
    }
}
