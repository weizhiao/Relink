use super::storage::{CommittedStorage, ContextId, KeyId, ModuleId, ModuleLease, ModuleSlot};
use super::unload::{UnloadGroup, UnloadedModule};
use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{EntitySet, SecondaryMap},
    image::{ModuleHandle, SearchPathPool},
    relocation::{RelocationArch, SymbolRegistry},
    runtime::DomainId,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::borrow::Borrow;

#[inline]
fn require_module<T>(id: ModuleId, module: Option<T>) -> Result<T> {
    module.ok_or_else(|| LinkerError::context(LinkContextError::ModuleNotCommitted { id }).into())
}

fn collect_import_modules<K, Arch, Tls, TargetMeta, SourceMeta>(
    target: &mut LinkContext<K, TargetMeta, Arch, Tls>,
    source: &LinkContext<K, SourceMeta, Arch, Tls>,
    slot: ModuleSlot,
    mapped: &mut SecondaryMap<ModuleSlot, ModuleSlot>,
    new_modules: &mut Vec<ModuleSlot>,
) -> Result<()>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    if mapped.get(slot).is_some() {
        return Ok(());
    }

    let id = source.committed.make_module_id(slot);
    let module = require_module(id, source.committed.module(slot))?;
    let key = target
        .committed
        .intern_key(source.committed.key(module.entry_key()).clone());
    if let Some(target_slot) = target
        .committed
        .canonical_module(key)
        .filter(|slot| target.committed.contains_module(*slot))
    {
        mapped.insert(slot, target_slot);
        return Ok(());
    }

    let target_slot = target.committed.intern_module(key);
    mapped.insert(slot, target_slot);
    for &dep in module.direct_deps() {
        collect_import_modules(target, source, dep, mapped, new_modules)?;
    }
    new_modules.push(slot);
    Ok(())
}

fn copy_new_modules<K, Arch, Tls, TargetMeta, SourceMeta>(
    target: &mut LinkContext<K, TargetMeta, Arch, Tls>,
    source: &LinkContext<K, SourceMeta, Arch, Tls>,
    new_modules: &[ModuleSlot],
    mapped: &SecondaryMap<ModuleSlot, ModuleSlot>,
) -> Result<()>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    TargetMeta: Default,
{
    let mut lifecycle = Vec::with_capacity(new_modules.len());
    for &slot in new_modules {
        let id = source.committed.make_module_id(slot);
        let module = require_module(id, source.committed.module(slot))?;
        let direct_deps = module
            .direct_deps()
            .iter()
            .map(|dep| {
                *mapped
                    .get(*dep)
                    .expect("dependency closure must contain every bound module")
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let target_slot = *mapped
            .get(slot)
            .expect("collected module must have a target slot");
        target.committed.insert(
            target_slot,
            module.handle().clone(),
            direct_deps,
            0,
            TargetMeta::default(),
        );
        lifecycle.push(target_slot);
    }
    target.committed.extend_lifecycle(&lifecycle);
    Ok(())
}

fn copy_import_closure<K, Arch, Tls, TargetMeta, SourceMeta>(
    target: &mut LinkContext<K, TargetMeta, Arch, Tls>,
    source: &LinkContext<K, SourceMeta, Arch, Tls>,
    roots: &[ModuleSlot],
) -> Result<SecondaryMap<ModuleSlot, ModuleSlot>>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    TargetMeta: Default,
{
    let mut mapped = SecondaryMap::default();
    let mut new_modules = Vec::new();
    for &root in roots {
        collect_import_modules(target, source, root, &mut mapped, &mut new_modules)?;
    }
    copy_new_modules(target, source, &new_modules, &mapped)?;
    Ok(mapped)
}

/// Local repository of committed modules and their dependency graph.
///
/// `LinkContext` is the mutable state paired with [`Linker`](crate::Linker).
/// It owns module ids, loaded module handles, aliases, and direct dependency
/// edges produced by successful linker loads.
///
/// Each context is one symbol namespace. Multiple contexts may target the same
/// runtime domain while retaining independent module graphs and GNU unique
/// symbol definitions. Module ids and key ids are branded with the namespace's
/// context identity so ids from different contexts cannot be mixed accidentally.
///
/// `Meta` stores state specific to one context entry. It is created independently
/// when a shared module is imported into another context and is detached with the
/// entry during unloading. State that must follow the underlying module allocation
/// belongs in the concrete module type instead.
pub struct LinkContext<K, Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()>
{
    pub(super) committed: CommittedStorage<K, Meta, Arch, Tls>,
    pub(super) symbols: Arc<SymbolRegistry<Arch, Tls>>,
    pub(crate) search_paths: SearchPathPool,
}

impl<K, Meta, Arch, Tls> LinkContext<K, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates an empty link context for `domain`.
    #[inline]
    pub fn new(domain: DomainId) -> Self {
        Self {
            committed: CommittedStorage::new(ContextId::fresh(), domain),
            symbols: Arc::new(SymbolRegistry::new()),
            search_paths: SearchPathPool::default(),
        }
    }

    /// Returns this context's symbol-namespace identity.
    #[inline]
    pub fn context_id(&self) -> ContextId {
        self.committed.context()
    }

    /// Returns this context's runtime domain.
    #[inline]
    pub fn domain_id(&self) -> DomainId {
        self.committed.domain()
    }

    /// Returns the shared dynamic search-path pool for target token configuration.
    ///
    /// Configure `$LIB` and `$PLATFORM` before loading modules so their
    /// `DT_RPATH` and `DT_RUNPATH` entries can be expanded once while loading.
    #[inline]
    pub fn search_paths_mut(&mut self) -> &mut SearchPathPool {
        &mut self.search_paths
    }
}

impl<K, Meta, Arch, Tls> LinkContext<K, Meta, Arch, Tls>
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
        self.committed.contains_id(id)
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

    /// Returns the committed module id associated with `key`.
    #[inline]
    pub fn module_id<Q>(&self, key: &Q) -> Option<ModuleId>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.committed
            .key_slot_for(key)
            .and_then(|slot| self.committed.module_for_key(slot))
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Resolves an interned key id to its committed module id.
    #[inline]
    pub fn resolve_key(&self, id: KeyId) -> Result<Option<ModuleId>> {
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
    ///
    /// The handle can be downcast to access state owned by a concrete module:
    ///
    /// ```ignore
    /// let module = context.get(id)?;
    /// let synthetic = module.downcast_ref::<SyntheticModule<MyArch, MyData>>();
    /// ```
    #[inline]
    pub fn get(&self, id: ModuleId) -> Result<&ModuleHandle<Arch, Tls>> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module(slot))?.handle())
    }

    /// Returns metadata owned by this context entry.
    #[inline]
    pub fn meta(&self, id: ModuleId) -> Result<&Meta> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module(slot))?.meta())
    }

    /// Returns mutable metadata owned by this context entry.
    #[inline]
    pub fn meta_mut(&mut self, id: ModuleId) -> Result<&mut Meta> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module_mut(slot))?.meta_mut())
    }

    /// Returns direct dependency modules for a committed module.
    #[inline]
    pub fn direct_deps(&self, id: ModuleId) -> Result<impl Iterator<Item = ModuleId> + '_> {
        let slot = self.committed.module_slot(id)?;
        Ok(require_module(id, self.committed.module(slot))?
            .direct_deps()
            .iter()
            .copied()
            .map(|slot| self.committed.make_module_id(slot)))
    }

    /// Iterates committed modules in load order.
    #[inline]
    pub fn load_order(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.committed
            .load_order()
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Inserts a retained module.
    ///
    /// The returned lease represents one direct acquisition. The canonical
    /// key must not already refer to a committed module.
    pub fn insert<R>(&mut self, key: K, module: R, direct_deps: Box<[K]>) -> Result<ModuleLease>
    where
        Meta: Default,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        self.insert_with_meta(key, module, direct_deps, Meta::default())
    }

    /// Inserts a group of retained modules whose dependencies may refer to
    /// other modules in the same group.
    ///
    /// All keys and dependency edges are resolved before any module is
    /// committed, so cyclic dependency graphs are supported. Returned leases
    /// follow the input order.
    pub fn insert_batch<R>(
        &mut self,
        modules: impl IntoIterator<Item = (K, R, Box<[K]>)>,
    ) -> Result<Vec<ModuleLease>>
    where
        Meta: Default,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        let modules = modules
            .into_iter()
            .map(|(key, module, deps)| (key, module.into(), deps))
            .collect::<Vec<_>>();
        for (_, module, _) in &modules {
            self.committed.ensure_domain(module.domain_id())?;
        }

        let mut group = EntitySet::default();
        let mut planned = Vec::with_capacity(modules.len());
        for (key, module, deps) in modules {
            let key = self.committed.intern_key(key);
            let slot = self.committed.intern_module(key);
            if self.committed.contains_module(slot) || !group.insert(slot) {
                return Err(LinkerError::context(LinkContextError::KeyOccupied {
                    id: self.committed.make_key_id(key),
                })
                .into());
            }
            planned.push((slot, module, deps));
        }

        let mut resolved = Vec::with_capacity(planned.len());
        for (slot, module, deps) in planned {
            let mut resolved_deps = Vec::with_capacity(deps.len());
            for key in deps.into_vec() {
                let key = self.committed.intern_key(key);
                let dep = self
                    .committed
                    .canonical_module(key)
                    .filter(|dep| self.committed.contains_module(*dep) || group.contains(*dep))
                    .or_else(|| self.committed.module_for_key(key))
                    .ok_or_else(|| {
                        LinkerError::context(LinkContextError::KeyNotCommitted {
                            id: self.committed.make_key_id(key),
                        })
                    })?;
                resolved_deps.push(dep);
            }
            resolved.push((slot, module, resolved_deps.into_boxed_slice()));
        }

        let mut leases = Vec::with_capacity(resolved.len());
        let mut lifecycle = Vec::with_capacity(resolved.len());
        for (slot, module, deps) in resolved {
            self.committed
                .insert(slot, module, deps, 1, Meta::default());
            lifecycle.push(slot);
            leases.push(ModuleLease::new(self.committed.make_module_id(slot)));
        }
        self.committed.extend_lifecycle(&lifecycle);
        Ok(leases)
    }

    /// Inserts a retained module with explicit context metadata.
    ///
    /// The returned lease represents one direct acquisition. The canonical
    /// key must not already refer to a committed module.
    pub fn insert_with_meta<R>(
        &mut self,
        key: K,
        module: R,
        direct_deps: Box<[K]>,
        meta: Meta,
    ) -> Result<ModuleLease>
    where
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        let module = module.into();
        self.committed.ensure_domain(module.domain_id())?;
        let key = self.committed.intern_key(key);
        if self
            .committed
            .canonical_module(key)
            .filter(|slot| self.committed.contains_module(*slot))
            .is_some()
        {
            return Err(LinkerError::context(LinkContextError::KeyOccupied {
                id: self.committed.make_key_id(key),
            })
            .into());
        }
        let mut resolved_deps = Vec::with_capacity(direct_deps.len());
        for key in direct_deps.into_vec() {
            let key = self.committed.intern_key(key);
            let module = self.committed.module_for_key(key).ok_or_else(|| {
                LinkerError::context(LinkContextError::KeyNotCommitted {
                    id: self.committed.make_key_id(key),
                })
            })?;
            resolved_deps.push(module);
        }
        let direct_deps = resolved_deps.into_boxed_slice();
        let module_slot = self.committed.intern_module(key);
        self.committed
            .insert(module_slot, module, direct_deps, 1, meta);
        self.committed.extend_lifecycle(&[module_slot]);
        Ok(ModuleLease::new(self.committed.make_module_id(module_slot)))
    }

    /// Registers an alternate key for an already committed module.
    ///
    /// A module committed directly under `alias` takes precedence over this
    /// alternate binding.
    ///
    /// Alias candidates retain registration order. If the current target is
    /// unloaded, lookup falls back to the next registered module.
    pub fn add_alias(&mut self, module_id: ModuleId, alias: K) -> Result<()> {
        let module_slot = self.committed.module_slot(module_id)?;
        if !self.committed.contains_module(module_slot) {
            return Err(LinkerError::context(LinkContextError::ModuleNotCommitted {
                id: module_id,
            })
            .into());
        }

        let alias = self.committed.intern_key(alias);
        self.committed.add_alias(alias, module_slot);
        Ok(())
    }

    /// Adds one direct acquisition of a committed module.
    ///
    /// Acquisitions are roots for dependency reachability. Dependency edges do
    /// not acquire their targets.
    pub fn acquire(&mut self, id: ModuleId) -> Result<ModuleLease> {
        let slot = self.committed.module_slot(id)?;
        require_module(id, self.committed.module_mut(slot))?.acquire_root();
        Ok(ModuleLease::new(id))
    }

    /// Converts one direct acquisition into a permanent context root.
    ///
    /// A pinned module and its dependency closure remain committed until the
    /// context itself is dropped. Pinning an already pinned module is
    /// idempotent, but still consumes the supplied acquisition.
    pub fn pin(&mut self, lease: ModuleLease) -> Result<()> {
        let id = lease.id();
        let slot = self.committed.module_slot(id)?;
        require_module(id, self.committed.module_mut(slot))?.pin_root();
        Ok(())
    }

    /// Releases one direct acquisition and detaches all modules that become unreachable.
    ///
    /// The returned collection keeps the entire unload group alive. Drop it
    /// after releasing any external registry lock to run pending finalizers.
    pub fn release(&mut self, lease: ModuleLease) -> Result<UnloadGroup<Meta, Arch, Tls>> {
        let id = lease.id();
        let slot = self.committed.module_slot(id)?;
        let refs = require_module(id, self.committed.module_mut(slot))?.release_root();
        if refs != 0 {
            return Ok(UnloadGroup::new(Vec::new()));
        }

        let mut reachable = EntitySet::default();
        let mut pending = self
            .committed
            .lifecycle()
            .filter(|slot| {
                self.committed
                    .module(*slot)
                    .is_some_and(|module| module.is_root())
            })
            .collect::<Vec<_>>();

        while let Some(slot) = pending.pop() {
            if !reachable.insert(slot) {
                continue;
            }
            let module_id = self.committed.make_module_id(slot);
            let module = require_module(module_id, self.committed.module(slot))?;
            pending.extend(module.direct_deps());
        }

        let unload_order = self
            .committed
            .lifecycle()
            .rev()
            .filter(|slot| !reachable.contains(*slot))
            .collect::<Vec<_>>();
        let mut modules = Vec::with_capacity(unload_order.len());
        for slot in unload_order {
            let id = self.committed.make_module_id(slot);
            let direct_deps = self
                .committed
                .module(slot)
                .expect("lifecycle order must refer to a committed module")
                .direct_deps()
                .iter()
                .copied()
                .map(|slot| self.committed.make_module_id(slot))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let (module, meta) = self.committed.take(slot);
            modules.push(UnloadedModule::new(id, module, direct_deps, meta));
        }
        self.committed.prune_removed();
        Ok(UnloadGroup::new(modules))
    }

    /// Returns the breadth-first dependency scope rooted at `root`.
    pub fn dependency_scope(&self, root: ModuleId) -> Result<Vec<ModuleId>> {
        let root_slot = self.committed.module_slot(root)?;
        let mut scope = Vec::new();
        let mut visited = EntitySet::default();
        let mut queue = VecDeque::new();
        visited.insert(root_slot);
        queue.push_back(root_slot);

        while let Some(slot) = queue.pop_front() {
            let id = self.committed.make_module_id(slot);
            let module = require_module(id, self.committed.module(slot))?;

            scope.push(id);
            for &dep in module.direct_deps() {
                let dep_id = self.committed.make_module_id(dep);
                require_module(dep_id, self.committed.module(dep))?;
                if visited.insert(dep) {
                    queue.push_back(dep);
                }
            }
        }

        Ok(scope)
    }

    /// Imports one module and its bound dependency closure from another context.
    ///
    /// The imported modules share their underlying [`ModuleHandle`] allocations
    /// with `source`, but receive ids in this context. The selected module gains
    /// one direct acquisition; imported dependencies do not become roots.
    /// Existing entry keys in this context take precedence over modules from
    /// `source`. Source aliases are not imported.
    ///
    /// The returned lease represents one direct acquisition in this context.
    pub fn import<SourceMeta>(
        &mut self,
        source: &LinkContext<K, SourceMeta, Arch, Tls>,
        id: ModuleId,
    ) -> Result<ModuleLease>
    where
        Meta: Default,
    {
        self.committed.ensure_domain(source.committed.domain())?;
        let source_root = source.committed.module_slot(id)?;
        require_module(id, source.committed.module(source_root))?;

        let mapped = copy_import_closure(self, source, &[source_root])?;

        let root = *mapped
            .get(source_root)
            .expect("imported root must have a target slot");
        let id = self.committed.make_module_id(root);
        require_module(id, self.committed.module_mut(root))?.acquire_root();
        Ok(ModuleLease::new(id))
    }

    /// Imports every acquired or pinned root from another context.
    ///
    /// Each source root receives one acquisition in this context, regardless of
    /// its acquisition count in `source`. Shared dependencies are copied once
    /// and remain dependency-only. Each returned lease represents one direct
    /// acquisition in this context. Source aliases are not imported because
    /// they belong to the source namespace.
    pub fn import_roots<SourceMeta>(
        &mut self,
        source: &LinkContext<K, SourceMeta, Arch, Tls>,
    ) -> Result<Box<[ModuleLease]>>
    where
        Meta: Default,
    {
        self.committed.ensure_domain(source.committed.domain())?;
        let roots = source
            .committed
            .lifecycle()
            .filter(|slot| {
                source
                    .committed
                    .module(*slot)
                    .is_some_and(|module| module.is_root())
            })
            .collect::<Vec<_>>();
        let mapped = copy_import_closure(self, source, &roots)?;
        let mut imported = Vec::with_capacity(roots.len());
        for root in roots {
            let root = *mapped
                .get(root)
                .expect("imported root must have a target slot");
            let id = self.committed.make_module_id(root);
            require_module(id, self.committed.module_mut(root))?.acquire_root();
            imported.push(ModuleLease::new(id));
        }
        Ok(imported.into_boxed_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::LinkContext;
    use crate::{
        Error, LinkContextError, LinkerError, Result,
        arch::NativeArch,
        elf::ElfSymbol,
        image::{Module, ModuleHandle, ModuleScope, ModuleState, SymbolExports, SyntheticModule},
        linker::ModuleId,
        memory::{ImageMemory, VmAddr},
        relocation::RelocationArch,
        runtime::DomainId,
        sync::Arc,
    };
    use alloc::{boxed::Box, string::String, vec::Vec};
    use spin::Mutex;

    struct FinalizeModule {
        name: &'static str,
        module: SyntheticModule<NativeArch>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Module for FinalizeModule {
        fn state(&self) -> &ModuleState {
            Module::<NativeArch>::state(&self.module)
        }

        fn name(&self) -> &str {
            Module::<NativeArch>::name(&self.module)
        }

        fn exports(&self) -> &dyn SymbolExports<<NativeArch as RelocationArch>::Layout> {
            Module::<NativeArch>::exports(&self.module)
        }

        fn memory(&self) -> &dyn ImageMemory {
            Module::<NativeArch>::memory(&self.module)
        }

        fn resolve_symbol(
            &self,
            symbol: &ElfSymbol<<NativeArch as RelocationArch>::Layout>,
        ) -> Result<VmAddr> {
            Module::<NativeArch>::resolve_symbol(&self.module, symbol)
        }

        fn domain_id(&self) -> DomainId {
            Module::<NativeArch>::domain_id(&self.module)
        }

        fn finalize(&self) -> Result<()> {
            self.calls.lock().push(self.name);
            Ok(())
        }
    }

    impl Drop for FinalizeModule {
        fn drop(&mut self) {
            let state = Module::<NativeArch>::state(&self.module);
            let _ = state.finalize(|| Module::<NativeArch>::finalize(self));
        }
    }

    fn finalize_module(
        name: &'static str,
        calls: &Arc<Mutex<Vec<&'static str>>>,
    ) -> ModuleHandle<NativeArch> {
        let module = ModuleHandle::new(FinalizeModule {
            name,
            module: SyntheticModule::empty(name),
            calls: Arc::clone(calls),
        });
        module.initialize().unwrap();
        module
    }

    fn domain_module(name: &'static str, domain: DomainId) -> SyntheticModule<NativeArch> {
        SyntheticModule::empty(name).with_domain(domain)
    }

    #[test]
    fn context_rejects_modules_from_another_domain() {
        let first = DomainId::new();
        let second = DomainId::new();
        let mut context = LinkContext::<&'static str, (), NativeArch>::new(first);

        let _ = context
            .insert("first", domain_module("first", first), Box::new([]))
            .unwrap();
        let error = context
            .insert("second", domain_module("second", second), Box::new([]))
            .unwrap_err();

        assert_eq!(context.domain_id(), first);
        assert!(matches!(
            error,
            Error::DomainMismatch { expected, actual }
                if expected == first && actual == second
        ));
    }

    #[test]
    fn module_scope_rejects_mixed_domains() {
        let first = DomainId::new();
        let second = DomainId::new();
        let mut scope = ModuleScope::<NativeArch>::new(first);
        scope.extend([
            domain_module("first", first),
            domain_module("second", second),
        ]);

        let error = scope.check_domain(first).unwrap_err();
        assert!(matches!(
            error,
            Error::DomainMismatch { expected, actual }
                if expected == first && actual == second
        ));
    }

    fn direct_deps<K: Clone + Ord>(
        context: &LinkContext<K, (), NativeArch>,
        id: ModuleId,
    ) -> Vec<ModuleId> {
        context
            .direct_deps(id)
            .expect("direct deps should resolve")
            .collect()
    }

    #[test]
    fn batch_insert_supports_cyclic_dependencies() {
        let mut context = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let leases = context
            .insert_batch([
                (
                    "first",
                    SyntheticModule::empty("first"),
                    Vec::from(["second"]).into_boxed_slice(),
                ),
                (
                    "second",
                    SyntheticModule::empty("second"),
                    Vec::from(["first"]).into_boxed_slice(),
                ),
            ])
            .unwrap();
        let first = leases[0].id();
        let second = leases[1].id();

        assert_eq!(direct_deps(&context, first), [second]);
        assert_eq!(direct_deps(&context, second), [first]);
        assert_eq!(context.dependency_scope(first).unwrap(), [first, second]);
    }

    #[test]
    fn ids_do_not_cross_contexts() {
        let mut first = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let first_root = first
            .insert("root", SyntheticModule::empty("first"), Box::new([]))
            .expect("failed to insert first module");
        let first_key = first.key_id(&"root").expect("root key should be interned");

        let mut second = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let second_root = second
            .insert("root", SyntheticModule::empty("second"), Box::new([]))
            .expect("failed to insert second module");
        let second_key = second.key_id(&"root").expect("root key should be interned");

        assert_ne!(first.context_id(), second.context_id());
        assert!(!Arc::ptr_eq(&first.symbols, &second.symbols));
        assert_ne!(first_root.id(), second_root.id());
        assert_ne!(first_key, second_key);
        assert!(second.contains_module(first_root.id()).is_err());
        assert!(second.get(first_root.id()).is_err());
        assert!(second.key(first_key).is_err());
        assert!(second.resolve_key(first_key).is_err());
        assert!(second.dependency_scope(first_root.id()).is_err());
        assert!(second.contains_module(second_root.id()).unwrap());
    }

    #[test]
    fn release_detaches_before_finalize() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let id = context
            .insert("removed", finalize_module("removed", &calls), Box::new([]))
            .unwrap();

        let module_id = id.id();
        let unloaded = context.release(id).unwrap();
        assert!(!context.contains_module(module_id).unwrap());
        assert!(calls.lock().is_empty());

        drop(unloaded);
        assert_eq!(calls.lock().as_slice(), &["removed"]);
    }

    #[test]
    fn pin_keeps_module_until_context_drop() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let dependency = context
            .insert(
                "dependency",
                finalize_module("dependency", &calls),
                Box::new([]),
            )
            .unwrap();
        let lease = context
            .insert(
                "pinned",
                finalize_module("pinned", &calls),
                Box::new(["dependency"]),
            )
            .unwrap();
        let id = lease.id();

        context.pin(lease).unwrap();
        assert!(context.release(dependency).unwrap().is_empty());
        let extra = context.acquire(id).unwrap();
        assert!(context.release(extra).unwrap().is_empty());
        assert!(context.contains_module(id).unwrap());
        assert!(calls.lock().is_empty());

        drop(context);
        assert_eq!(calls.lock().as_slice(), &["pinned", "dependency"]);
    }

    #[test]
    fn reload_invalidates_old_module_id() {
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let first = context
            .insert("module", SyntheticModule::empty("first"), Box::new([]))
            .unwrap();
        let first_id = first.id();
        let key_id = context.key_id(&"module").unwrap();

        drop(context.release(first).unwrap());
        assert!(!context.contains_module(first_id).unwrap());
        assert_eq!(context.module_id(&"module"), None);

        let second = context
            .insert("module", SyntheticModule::empty("second"), Box::new([]))
            .unwrap();
        assert_ne!(second.id(), first_id);
        assert_eq!(context.key_id(&"module"), Some(key_id));
        assert_eq!(context.module_id(&"module"), Some(second.id()));
        let error = match context.get(first_id) {
            Ok(_) => panic!("stale module id should fail"),
            Err(error) => error,
        };
        let Error::Linker(LinkerError::Context { reason }) = error else {
            panic!("unexpected stale module error: {error}");
        };
        assert!(matches!(*reason, LinkContextError::StaleModuleId { id } if id == first_id));
    }

    #[test]
    fn shared_module_finalizes_after_last_handle() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let module = finalize_module("shared", &calls);
        let mut first = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let mut second = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let first_id = first
            .insert("shared", module.clone(), Box::new([]))
            .unwrap();
        let second_id = second
            .insert("shared", module.clone(), Box::new([]))
            .unwrap();

        drop(first.release(first_id).unwrap());
        assert!(calls.lock().is_empty());

        drop(second.release(second_id).unwrap());
        assert!(calls.lock().is_empty());

        drop(module);
        assert_eq!(calls.lock().as_slice(), &["shared"]);
    }

    #[test]
    fn module_data_outlives_context_entry() {
        let module = ModuleHandle::new(
            SyntheticModule::empty("stateful").with_user_data(String::from("module data")),
        );
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let id = context
            .insert("stateful", module.clone(), Box::new([]))
            .unwrap();

        drop(context.release(id).unwrap());

        let module = module
            .downcast_ref::<SyntheticModule<NativeArch, String>>()
            .unwrap();
        assert_eq!(module.user_data(), "module data");
    }

    #[test]
    fn context_drop_finalizes_in_lifecycle_order() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        {
            let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
            let _ = context
                .insert("dep", finalize_module("dep", &calls), Box::new([]))
                .unwrap();
            let _ = context
                .insert("root", finalize_module("root", &calls), Box::new(["dep"]))
                .unwrap();
        }

        assert_eq!(calls.lock().as_slice(), &["root", "dep"]);
    }

    #[test]
    fn releases_all_acquisitions() {
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let id = context
            .insert("root", SyntheticModule::empty("root"), Box::new([]))
            .unwrap();
        let module_id = id.id();
        let second = context.acquire(module_id).unwrap();

        assert!(context.release(id).unwrap().is_empty());
        assert!(context.contains_module(module_id).unwrap());

        let unloaded = context.release(second).unwrap();
        assert_eq!(unloaded.len(), 1);
        assert!(!context.contains_module(module_id).unwrap());
    }

    #[test]
    fn shared_dependencies_remain_reachable() {
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let shared = context
            .insert("shared", SyntheticModule::empty("shared"), Box::new([]))
            .unwrap();
        let first = context
            .insert(
                "first",
                SyntheticModule::empty("first"),
                Box::new(["shared"]),
            )
            .unwrap();
        let second = context
            .insert(
                "second",
                SyntheticModule::empty("second"),
                Box::new(["shared"]),
            )
            .unwrap();

        let first_id = first.id();
        let shared_id = shared.id();
        assert!(context.release(shared).unwrap().is_empty());
        let unloaded = context.release(first).unwrap();
        assert_eq!(unloaded.modules()[0].id(), first_id);
        assert!(context.contains_module(shared_id).unwrap());

        let unloaded = context.release(second).unwrap();
        assert_eq!(unloaded.modules()[0].direct_deps(), [shared_id]);
        assert_eq!(
            unloaded
                .modules()
                .iter()
                .map(|entry| entry.module().name())
                .collect::<Vec<_>>(),
            ["second", "shared"]
        );
        assert!(context.is_empty());
    }

    #[test]
    fn finalizes_dependents_before_dependencies() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut context = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let dep = context
            .insert("dep", finalize_module("dep", &calls), Box::new([]))
            .unwrap();
        let root = context
            .insert("root", finalize_module("root", &calls), Box::new(["dep"]))
            .unwrap();

        assert!(context.release(dep).unwrap().is_empty());
        let unloaded = context.release(root).unwrap();
        drop(unloaded);

        assert_eq!(calls.lock().as_slice(), &["root", "dep"]);
    }

    #[test]
    fn alias_growth_preserves_bound_dependencies() {
        let mut context = LinkContext::<String, (), NativeArch>::new(DomainId::PROCESS);
        let canonical = context
            .insert(
                String::from("canonical"),
                SyntheticModule::empty("canonical"),
                Box::new([]),
            )
            .expect("failed to insert canonical module");
        let canonical_id = canonical.id();
        context
            .add_alias(canonical_id, String::from("alias"))
            .expect("failed to add alias");
        let alias_id = context
            .key_id("alias")
            .expect("dependency key should be interned before root insertion");
        let root = context
            .insert(
                String::from("root"),
                SyntheticModule::empty("root"),
                Box::new([String::from("alias")]),
            )
            .expect("failed to insert root module");
        let root_id = root.id();
        let replacement = context
            .insert(
                String::from("replacement"),
                SyntheticModule::empty("replacement"),
                Box::new([]),
            )
            .expect("failed to insert replacement module");
        let replacement_id = replacement.id();
        context
            .add_alias(replacement_id, String::from("alias"))
            .expect("failed to add alias fallback");

        assert!(context.resolve_key(alias_id).unwrap().is_some());
        assert_eq!(context.key_id("alias"), Some(alias_id));
        assert_eq!(context.resolve_key(alias_id).unwrap(), Some(canonical_id));
        assert_eq!(direct_deps(&context, root_id), [canonical_id]);
        assert_eq!(
            context
                .dependency_scope(root_id)
                .expect("dependency scope should resolve")
                .as_slice(),
            &[root_id, canonical_id]
        );
    }

    #[test]
    fn alias_uses_registration_order() {
        let mut context = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let first = context
            .insert("first", SyntheticModule::empty("first"), Box::new([]))
            .expect("failed to insert first module");
        let second = context
            .insert("second", SyntheticModule::empty("second"), Box::new([]))
            .expect("failed to insert second module");
        let first_id = first.id();
        let second_id = second.id();

        context
            .add_alias(first_id, "alias")
            .expect("failed to add alias");
        let alias = context.key_id(&"alias").expect("alias key should exist");
        assert_eq!(context.resolve_key(alias).unwrap(), Some(first_id));
        context
            .add_alias(second_id, "alias")
            .expect("failed to add alias fallback");
        context
            .add_alias(second_id, "alias")
            .expect("failed to keep alias fallback");
        assert_eq!(context.resolve_key(alias).unwrap(), Some(first_id));

        assert_eq!(context.release(first).unwrap().len(), 1);
        assert_eq!(context.resolve_key(alias).unwrap(), Some(second_id));
        assert_eq!(context.release(second).unwrap().len(), 1);
        assert_eq!(context.resolve_key(alias).unwrap(), None);
    }

    #[test]
    fn insert_rejects_occupied_key() {
        let mut context = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let root = context
            .insert("root", SyntheticModule::empty("old-root"), Box::new([]))
            .expect("failed to insert root module");
        let root_id = root.id();
        let root_key = context.key_id(&"root").expect("root key should exist");

        let error = context
            .insert("root", SyntheticModule::empty("new-root"), Box::new([]))
            .expect_err("occupied key must not be replaced");
        let Error::Linker(LinkerError::Context { reason }) = error else {
            panic!("unexpected insertion error: {error}");
        };
        assert!(matches!(*reason, LinkContextError::KeyOccupied { id } if id == root_key));
        assert_eq!(context.key_id(&"root"), Some(root_key));
        assert_eq!(context.resolve_key(root_key).unwrap(), Some(root_id));
        assert_eq!(context.module_key(root_id).unwrap(), &"root");
        assert!(direct_deps(&context, root_id).is_empty());
    }

    #[test]
    fn canonical_key_takes_precedence_over_alias() {
        let mut context = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let root = context
            .insert("root", SyntheticModule::empty("root"), Box::new([]))
            .expect("failed to insert root module");
        let root_id = root.id();
        context
            .add_alias(root_id, "alias")
            .expect("failed to add alias");
        let alias = context.key_id(&"alias").expect("alias key should exist");
        let dep_module = context
            .insert("dep", SyntheticModule::empty("dep"), Box::new([]))
            .expect("failed to insert dependency");
        let dep_module_id = dep_module.id();

        let canonical = context
            .insert("alias", SyntheticModule::empty("alias"), Box::new(["dep"]))
            .expect("failed to insert canonical module");
        assert_ne!(canonical.id(), root_id);
        assert_eq!(context.resolve_key(alias).unwrap(), Some(canonical.id()));
        assert_eq!(context.module_key(root_id).unwrap(), &"root");
        assert_eq!(context.module_key(canonical.id()).unwrap(), &"alias");
        assert_eq!(direct_deps(&context, canonical.id()), [dep_module_id]);

        assert_eq!(context.release(canonical).unwrap().len(), 1);
        assert_eq!(context.resolve_key(alias).unwrap(), Some(root_id));
    }

    #[test]
    fn import_roots_preserves_bound_dependencies() {
        let mut source = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let canonical = source
            .insert(
                "canonical",
                SyntheticModule::empty("canonical"),
                Box::new([]),
            )
            .expect("failed to insert canonical module");
        let canonical_id = canonical.id();
        source
            .add_alias(canonical_id, "alias")
            .expect("failed to add alias");
        let root = source
            .insert("root", SyntheticModule::empty("root"), Box::new(["alias"]))
            .expect("failed to insert root module");
        let root_id = root.id();
        let replacement = source
            .insert(
                "replacement",
                SyntheticModule::empty("replacement"),
                Box::new([]),
            )
            .expect("failed to insert replacement module");
        source
            .add_alias(replacement.id(), "alias")
            .expect("failed to add alias fallback");

        let mut target = LinkContext::<&'static str, (), NativeArch>::new(DomainId::PROCESS);
        let imported = target
            .import_roots(&source)
            .expect("failed to import context roots");
        assert_eq!(imported.len(), 3);
        let target_root = target
            .module_id("root")
            .expect("root module should be copied");
        let target_canonical = target
            .module_id("canonical")
            .expect("canonical key should be copied");
        let target_replacement = target
            .module_id("replacement")
            .expect("replacement key should be copied");

        assert_eq!(direct_deps(&source, root_id), [canonical_id]);
        assert_eq!(
            source
                .dependency_scope(root_id)
                .expect("source scope should resolve")
                .as_slice(),
            &[root_id, canonical_id]
        );
        assert_eq!(direct_deps(&target, target_root), [target_canonical]);
        assert_eq!(target.module_id("alias"), None);
        assert!(target.contains_module(target_replacement).unwrap());
        assert_eq!(
            target
                .dependency_scope(target_root)
                .expect("target scope should resolve")
                .as_slice(),
            &[target_root, target_canonical]
        );
    }

    #[test]
    fn imported_modules_have_context_local_metadata() {
        let mut source = LinkContext::<&'static str, usize>::new(DomainId::PROCESS);
        let source_lease = source
            .insert_with_meta("module", SyntheticModule::empty("module"), Box::new([]), 7)
            .unwrap();
        let source_id = source_lease.id();

        let mut target = LinkContext::<&'static str, String>::new(DomainId::PROCESS);
        let target_lease = target.import(&source, source_id).unwrap();
        let target_id = target_lease.id();

        assert!(
            source
                .get(source_id)
                .unwrap()
                .ptr_eq(target.get(target_id).unwrap())
        );
        assert_eq!(source.meta(source_id).unwrap(), &7);
        assert_eq!(target.meta(target_id).unwrap(), "");
        target.meta_mut(target_id).unwrap().push_str("target");
        assert_eq!(source.meta(source_id).unwrap(), &7);

        let target_unload = target.release(target_lease).unwrap();
        assert_eq!(target_unload.modules()[0].meta(), "target");
        let source_unload = source.release(source_lease).unwrap();
        assert_eq!(*source_unload.modules()[0].meta(), 7);
    }

    #[test]
    fn import_copies_only_dependency_closure() {
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let source_dep = source
            .insert("dep", SyntheticModule::empty("dep"), Box::new([]))
            .unwrap();
        let source_root = source
            .insert("root", SyntheticModule::empty("root"), Box::new(["dep"]))
            .unwrap();
        let source_dep_id = source_dep.id();
        let source_root_id = source_root.id();
        let _ = source
            .insert(
                "unrelated",
                SyntheticModule::empty("unrelated"),
                Box::new([]),
            )
            .unwrap();

        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let root = target.import(&source, source_root_id).unwrap();
        let root_id = root.id();
        let dep = target
            .module_id("dep")
            .expect("dependency should be imported");

        assert!(!target.contains_key(&"unrelated"));
        assert!(
            target
                .get(root_id)
                .unwrap()
                .ptr_eq(source.get(source_root_id).unwrap())
        );
        assert!(
            target
                .get(dep)
                .unwrap()
                .ptr_eq(source.get(source_dep_id).unwrap())
        );
        assert_eq!(target.dependency_scope(root_id).unwrap(), [root_id, dep]);

        let unloaded = target.release(root).unwrap();
        assert_eq!(
            unloaded.len(),
            2,
            "dependency must not inherit source roots"
        );
        assert!(source.contains_module(source_root_id).unwrap());
        assert!(source.contains_module(source_dep_id).unwrap());
    }

    #[test]
    fn import_handles_dependency_cycles() {
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let source_modules = source
            .insert_batch([
                (
                    "first",
                    SyntheticModule::empty("first"),
                    Vec::from(["second"]).into_boxed_slice(),
                ),
                (
                    "second",
                    SyntheticModule::empty("second"),
                    Vec::from(["first"]).into_boxed_slice(),
                ),
            ])
            .unwrap();
        let source_first = source_modules[0].id();

        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let first = target.import(&source, source_first).unwrap();
        let first_id = first.id();
        let second = target.module_id("second").unwrap();

        assert_eq!(
            target.dependency_scope(first_id).unwrap(),
            [first_id, second]
        );
        assert_eq!(target.release(first).unwrap().len(), 2);
    }

    #[test]
    fn import_stops_at_existing_module() {
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let _ = source
            .insert("dep", SyntheticModule::empty("dep"), Box::new([]))
            .unwrap();
        let source_root = source
            .insert(
                "root",
                SyntheticModule::empty("source-root"),
                Box::new(["dep"]),
            )
            .unwrap();

        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let existing = target
            .insert("root", SyntheticModule::empty("target-root"), Box::new([]))
            .unwrap();
        let existing_id = existing.id();
        let imported = target.import(&source, source_root.id()).unwrap();

        assert_eq!(imported.id(), existing_id);
        assert!(!target.contains_key(&"dep"));
        assert_eq!(target.release(imported).unwrap().len(), 0);
        let unloaded = target.release(existing).unwrap();
        assert_eq!(unloaded.len(), 1);
        assert_eq!(unloaded.modules()[0].id(), existing_id);
    }

    #[test]
    fn import_uses_entry_key() {
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let source_root = source
            .insert(
                "canonical",
                SyntheticModule::empty("canonical"),
                Box::new([]),
            )
            .unwrap();
        source.add_alias(source_root.id(), "alias").unwrap();

        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let imported = target.import(&source, source_root.id()).unwrap();

        assert_eq!(target.module_key(imported.id()).unwrap(), &"canonical");
        assert!(target.contains_key(&"canonical"));
        assert!(!target.contains_key(&"alias"));
    }

    #[test]
    fn import_does_not_follow_target_alias() {
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let source_root = source
            .insert("source", SyntheticModule::empty("source"), Box::new([]))
            .unwrap();
        source.add_alias(source_root.id(), "alias").unwrap();

        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let existing = target
            .insert("target", SyntheticModule::empty("target"), Box::new([]))
            .unwrap();
        let existing_id = existing.id();
        target.add_alias(existing_id, "alias").unwrap();
        let imported = target.import(&source, source_root.id()).unwrap();

        assert_ne!(imported.id(), existing_id);
        assert!(target.contains_key(&"source"));
        assert_eq!(target.module_id("alias"), Some(existing_id));
    }

    #[test]
    fn import_roots_preserves_lifecycle() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let _ = source
            .insert("dep", finalize_module("dep", &calls), Box::new([]))
            .unwrap();
        let _ = source
            .insert("root", finalize_module("root", &calls), Box::new(["dep"]))
            .unwrap();
        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let imported = target.import_roots(&source).unwrap();
        let target_dep_id = target.module_id("dep").unwrap();
        let target_root_id = target.module_id("root").unwrap();

        drop(source);
        let mut imported = imported.into_vec().into_iter();
        let target_dep = imported.next().unwrap();
        let target_root = imported.next().unwrap();
        assert_eq!(target_dep.id(), target_dep_id);
        assert_eq!(target_root.id(), target_root_id);
        assert!(target.release(target_dep).unwrap().is_empty());
        drop(target.release(target_root).unwrap());
        assert_eq!(calls.lock().as_slice(), &["root", "dep"]);
    }

    #[test]
    fn import_roots_acquires_each_root_once() {
        let mut source = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let source_root = source
            .insert("root", SyntheticModule::empty("root"), Box::new([]))
            .unwrap();
        let source_root_id = source_root.id();
        let _second = source.acquire(source_root_id).unwrap();

        let mut target = LinkContext::<&'static str>::new(DomainId::PROCESS);
        let imported = target.import_roots(&source).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(
            target
                .release(imported.into_vec().pop().unwrap())
                .unwrap()
                .len(),
            1
        );
        assert!(source.contains_module(source_root_id).unwrap());
    }
}
