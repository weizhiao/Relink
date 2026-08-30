use super::storage::{CommittedStorage, ContextId, ModuleId, ModuleKey, ModuleLease};
use super::unload::{UnloadGroup, UnloadedModule};
use crate::{
    Result,
    arch::NativeArch,
    entity::EntitySet,
    image::{GlobalScope, Module, ModuleScope, SearchPathPool},
    memory::VmAddr,
    relocation::{RelocationArch, SymbolRegistry},
    runtime::DomainId,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{collections::VecDeque, vec::Vec};

/// Local repository of committed modules and their dependency graph.
///
/// `LinkContext` is the mutable state paired with [`Linker`](crate::Linker).
/// It owns module ids, loaded module handles, aliases, and direct dependency
/// edges produced by successful linker loads.
///
/// Each context is one symbol namespace. Multiple contexts may target the same
/// runtime domain while retaining independent module graphs and GNU unique
/// symbol definitions. Module ids are branded with the namespace's context
/// identity so ids from different contexts cannot be mixed accidentally.
///
/// `Meta` stores state specific to one context entry. It is created independently
/// when a shared module is imported into another context and is detached with the
/// entry during unloading. State that must follow the underlying module allocation
/// belongs in the concrete module type instead.
pub struct LinkContext<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    pub(super) global: GlobalScope<Arch, Tls>,
    pub(super) committed: CommittedStorage<Meta, Arch, Tls>,
    pub(super) symbols: Arc<SymbolRegistry<Arch, Tls>>,
    pub(crate) search_paths: SearchPathPool,
}

impl LinkContext<(), NativeArch, ()> {
    /// Creates an empty namespace targeting the current native process.
    ///
    /// Use [`new`](Self::new) when the namespace needs custom metadata, an
    /// explicit target architecture or TLS resolver, or another runtime domain.
    #[inline]
    pub fn for_process() -> Self {
        Self::new(DomainId::PROCESS)
    }
}

impl<Meta, Arch, Tls> LinkContext<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates an empty link context for `domain`.
    #[inline]
    pub fn new(domain: DomainId) -> Self {
        Self {
            global: GlobalScope::new(domain),
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

    /// Returns this namespace's live global symbol scope.
    ///
    /// The scope is updated by [`promote_global`](Self::promote_global),
    /// [`extend_global`](Self::extend_global), and unloading. It can be supplied
    /// to a standalone [`Relocator`](crate::Relocator) run when that relocation
    /// should share this context's global namespace.
    #[inline]
    pub const fn global_scope(&self) -> &GlobalScope<Arch, Tls> {
        &self.global
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

impl<Meta, Arch, Tls> LinkContext<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Returns whether no modules have been committed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    /// Returns whether the context contains the committed module `id`.
    #[inline]
    pub fn contains_module(&self, id: ModuleId) -> Result<bool> {
        self.committed.contains_id(id)
    }

    /// Returns the committed module id associated with `key`.
    #[inline]
    pub fn module_id(&self, key: &str) -> Option<ModuleId> {
        self.committed
            .module_for_key(key)
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Returns the committed module id for this exact loaded module instance.
    ///
    /// A different instance loaded from the same source does not match.
    #[inline]
    pub fn module_id_for(&self, module: &dyn Module<Arch, Tls>) -> Option<ModuleId> {
        self.committed
            .module_for_binding(module.state().instance_id())
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Returns the first committed module whose runtime memory contains `addr`.
    ///
    /// Overlapping module ranges are resolved in load order.
    pub fn module_id_at(&self, addr: VmAddr) -> Option<ModuleId> {
        self.load_order().find(|id| {
            self.module(*id)
                .is_ok_and(|module| module.memory().range_at(addr).is_some())
        })
    }

    /// Returns the representative key associated with a committed module id.
    #[inline]
    pub fn module_key(&self, id: ModuleId) -> Result<&ModuleKey> {
        let module_slot = self.committed.module_slot(id)?;
        let module = self
            .committed
            .module(module_slot)
            .expect("validated module id must refer to committed state");
        Ok(module.entry_key())
    }

    /// Returns the committed module associated with an id.
    ///
    /// The returned module can be downcast to access state owned by a concrete type:
    ///
    /// ```ignore
    /// let module = context.module(id)?;
    /// let synthetic = module.downcast_ref::<SyntheticModule<MyArch, MyData>>();
    /// let elf = module.downcast_ref::<ElfModule<MyData, MyArch, MyRegion, MyTls>>();
    /// ```
    #[inline]
    pub fn module(&self, id: ModuleId) -> Result<&dyn Module<Arch, Tls>> {
        let slot = self.committed.module_slot(id)?;
        Ok(self
            .committed
            .module(slot)
            .expect("validated module id must refer to committed state")
            .handle()
            .as_ref())
    }

    /// Returns metadata owned by this context entry.
    #[inline]
    pub fn meta(&self, id: ModuleId) -> Result<&Meta> {
        let slot = self.committed.module_slot(id)?;
        Ok(self
            .committed
            .module(slot)
            .expect("validated module id must refer to committed state")
            .meta())
    }

    /// Returns mutable metadata owned by this context entry.
    #[inline]
    pub fn meta_mut(&mut self, id: ModuleId) -> Result<&mut Meta> {
        let slot = self.committed.module_slot(id)?;
        Ok(self
            .committed
            .module_mut(slot)
            .expect("validated module id must refer to committed state")
            .meta_mut())
    }

    /// Returns direct dependency modules for a committed module.
    #[inline]
    pub fn direct_deps(&self, id: ModuleId) -> Result<impl Iterator<Item = ModuleId> + '_> {
        let slot = self.committed.module_slot(id)?;
        Ok(self
            .committed
            .module(slot)
            .expect("validated module id must refer to committed state")
            .direct_deps()
            .iter()
            .copied()
            .map(|slot| self.committed.make_module_id(slot)))
    }

    /// Returns modules retained by this module's runtime symbol bindings.
    #[inline]
    pub fn reloc_deps(&self, id: ModuleId) -> Result<impl Iterator<Item = ModuleId> + '_> {
        let slot = self.committed.module_slot(id)?;
        let deps = self
            .committed
            .module(slot)
            .expect("validated module id must refer to committed state")
            .handle()
            .state()
            .with_effects(|bindings, _| {
                bindings
                    .iter()
                    .filter_map(|binding| self.committed.module_for_binding(*binding))
                    .map(|slot| self.committed.make_module_id(slot))
                    .collect::<Vec<_>>()
            });
        Ok(deps.into_iter())
    }

    /// Iterates committed modules in load order.
    #[inline]
    pub fn load_order(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.committed
            .lifecycle()
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Registers an alternate key for an already committed module.
    ///
    /// Candidates retain registration order. If the current target is
    /// unloaded, lookup falls back to the next registered module.
    pub fn add_alias(&mut self, module_id: ModuleId, alias: impl Into<ModuleKey>) -> Result<()> {
        let module_slot = self.committed.module_slot(module_id)?;
        self.committed.bind_key(alias.into(), module_slot);
        Ok(())
    }

    /// Adds one direct acquisition of a committed module.
    ///
    /// Acquisitions are roots for dependency reachability. Dependency edges do
    /// not acquire their targets.
    pub fn acquire(&mut self, id: ModuleId) -> Result<ModuleLease> {
        let slot = self.committed.module_slot(id)?;
        self.committed
            .module_mut(slot)
            .expect("validated module id must refer to committed state")
            .acquire_root();
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
        self.committed
            .module_mut(slot)
            .expect("validated module id must refer to committed state")
            .pin_root();
        Ok(())
    }

    /// Adds a module and its direct dependency closure to this namespace's
    /// global symbol lookup order.
    ///
    /// Promotion changes visibility only. Existing leases and dependency
    /// reachability continue to control module lifetime.
    pub fn promote_global(&mut self, root: ModuleId) -> Result<()> {
        let root = self.committed.module_slot(root)?;
        let mut visited = EntitySet::default();
        let mut queue = VecDeque::from([root]);
        let mut global = self.global.write();
        while let Some(slot) = queue.pop_front() {
            if !visited.insert(slot) {
                continue;
            }
            let module = self
                .committed
                .module(slot)
                .expect("global traversal must only contain committed modules");
            if !global
                .iter()
                .any(|candidate| candidate.source_id() == module.handle().source_id())
            {
                global.push(module.handle().clone());
            }
            queue.extend(module.direct_deps().iter().copied());
        }
        Ok(())
    }

    /// Appends existing modules themselves to global lookup order.
    ///
    /// Unlike [`promote_global`](Self::promote_global), this method does not
    /// traverse dependency edges. It is intended for importing an existing
    /// namespace whose complete lookup order is already known, such as the
    /// initial process link map. Module lifetime remains controlled by leases,
    /// pins, and dependency reachability.
    pub fn extend_global(&mut self, modules: &[ModuleId]) -> Result<()> {
        for &id in modules {
            self.committed.module_slot(id)?;
        }

        let mut global = self.global.write();
        for &id in modules {
            let slot = self
                .committed
                .module_slot(id)
                .expect("validated global module id must remain committed");
            let module = self
                .committed
                .module(slot)
                .expect("validated global module id must refer to committed state");
            if !global
                .iter()
                .any(|candidate| candidate.source_id() == module.handle().source_id())
            {
                global.push(module.handle().clone());
            }
        }
        Ok(())
    }

    /// Releases one direct acquisition and detaches all modules that become unreachable.
    ///
    /// This consumes the corresponding [`ModuleLease`]. Dropping a lease without
    /// calling this method leaves the acquisition active until this context is dropped.
    ///
    /// The returned collection keeps the entire unload group alive. Drop it
    /// after releasing any external registry lock to run pending finalizers.
    pub fn release(&mut self, lease: ModuleLease) -> Result<UnloadGroup<Meta, Arch, Tls>> {
        let id = lease.id();
        let slot = self.committed.module_slot(id)?;
        let refs = self
            .committed
            .module_mut(slot)
            .expect("validated module id must refer to committed state")
            .release_root();
        if refs != 0 {
            return Ok(UnloadGroup::new(Vec::new()));
        }

        let mut global = self.global.write();
        for provider in self.symbols.take_pending_pins() {
            if let Some(slot) = self.committed.module_for_binding(provider) {
                self.committed
                    .module_mut(slot)
                    .expect("lazy pin provider must remain committed")
                    .pin();
            }
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
            let module = self
                .committed
                .module(slot)
                .expect("lifecycle must only contain committed modules");
            pending.extend(module.direct_deps().iter().copied());
            module.handle().state().with_effects(|bindings, _| {
                pending.extend(
                    bindings
                        .iter()
                        .filter_map(|binding| self.committed.module_for_binding(*binding)),
                );
            });
        }

        let unload_order = self
            .committed
            .lifecycle()
            .rev()
            .filter(|slot| !reachable.contains(*slot))
            .collect::<Vec<_>>();
        global.retain(|module| {
            self.committed
                .module_for_source(module.source_id())
                .is_some_and(|slot| reachable.contains(slot))
        });
        let mut modules = Vec::with_capacity(unload_order.len());
        for slot in unload_order {
            let id = self.committed.make_module_id(slot);
            let (module, retained, meta) = self.committed.remove(slot);
            modules.push(UnloadedModule::new(id, module, retained, meta));
        }
        self.committed.prune_lifecycle();
        Ok(UnloadGroup::new(modules))
    }

    /// Returns the retained breadth-first dependency scope rooted at `root`.
    pub fn load_group(&mut self, root: ModuleId) -> Result<ModuleScope<Arch, Tls>> {
        let root_slot = self.committed.module_slot(root)?;
        let root_module = self
            .committed
            .module(root_slot)
            .expect("validated module id must refer to committed state");
        if let Some(scope) = root_module.load_group() {
            return Ok(scope.clone());
        }

        let mut scope = ModuleScope::new(self.domain_id());
        let mut visited = EntitySet::default();
        let mut queue = VecDeque::new();
        visited.insert(root_slot);
        queue.push_back(root_slot);

        while let Some(slot) = queue.pop_front() {
            let module = self
                .committed
                .module(slot)
                .expect("load group traversal must only contain committed modules");

            scope.push(module.handle().clone());
            for &dep in module.direct_deps() {
                if visited.insert(dep) {
                    queue.push_back(dep);
                }
            }
        }

        self.committed
            .module_mut(root_slot)
            .expect("validated module id must refer to committed state")
            .cache_load_group(scope.clone());
        Ok(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::LinkContext;
    use crate::{
        Error, LinkContextError, LinkerError, Result,
        arch::NativeArch,
        elf::ElfSymbol,
        image::{
            Module, ModuleHandle, ModuleInstanceId, ModuleScope, ModuleState, SymbolExports,
            SyntheticModule,
        },
        linker::{GraphModule, ModuleId},
        memory::{ImageMemory, VmAddr},
        relocation::RelocationArch,
        runtime::DomainId,
        sync::Arc,
    };
    use alloc::{string::String, vec::Vec};
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

    fn node(key: &str, module: impl Into<ModuleHandle<NativeArch>>) -> GraphModule<(), NativeArch> {
        GraphModule::new(key, module)
    }

    fn instance(context: &LinkContext<(), NativeArch>, id: ModuleId) -> ModuleInstanceId {
        context.module(id).unwrap().state().instance_id()
    }

    fn load_group_names(context: &mut LinkContext<(), NativeArch>, root: ModuleId) -> Vec<String> {
        context
            .load_group(root)
            .unwrap()
            .iter()
            .map(|module| String::from(module.name()))
            .collect()
    }

    #[test]
    fn load_group_is_cached_by_its_root_entry() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let dependency = context
            .insert(node("dependency", SyntheticModule::empty("dependency")))
            .unwrap();
        let root = context
            .insert(
                node("root", SyntheticModule::empty("root"))
                    .dependencies([instance(&context, dependency.id())]),
            )
            .unwrap();

        let first = context.load_group(root.id()).unwrap();
        let second = context.load_group(root.id()).unwrap();

        assert_eq!(first.as_ptr(), second.as_ptr());
        assert_eq!(
            load_group_names(&mut context, root.id()),
            ["root", "dependency"]
        );
    }

    #[test]
    fn process_context_uses_native_defaults() {
        let context = LinkContext::for_process();

        assert_eq!(context.domain_id(), DomainId::PROCESS);
        assert!(context.is_empty());
    }

    #[test]
    fn module_id_for_tracks_committed_instance() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let module = ModuleHandle::new(SyntheticModule::empty("module"));
        let lease = context.insert(node("module", module.clone())).unwrap();

        assert_eq!(context.module_id_for(module.as_ref()), Some(lease.id()));

        let unloaded = context.release(lease).unwrap();
        assert_eq!(context.module_id_for(module.as_ref()), None);
        drop(unloaded);
    }

    #[test]
    fn context_rejects_modules_from_another_domain() {
        let first = DomainId::new();
        let second = DomainId::new();
        let mut context = LinkContext::<(), NativeArch>::new(first);

        let _ = context
            .insert(node("first", domain_module("first", first)))
            .unwrap();
        let error = context
            .insert(node("second", domain_module("second", second)))
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

    fn direct_deps(context: &LinkContext<(), NativeArch>, id: ModuleId) -> Vec<ModuleId> {
        context
            .direct_deps(id)
            .expect("direct deps should resolve")
            .collect()
    }

    #[test]
    fn module_ids_do_not_cross_contexts() {
        let mut first = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let first_root = first
            .insert(node("root", SyntheticModule::empty("first")))
            .expect("failed to insert first module");

        let mut second = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let second_root = second
            .insert(node("root", SyntheticModule::empty("second")))
            .expect("failed to insert second module");

        assert_ne!(first.context_id(), second.context_id());
        assert!(!Arc::ptr_eq(&first.symbols, &second.symbols));
        assert_ne!(first_root.id(), second_root.id());
        assert!(second.contains_module(first_root.id()).is_err());
        assert!(second.module(first_root.id()).is_err());
        assert!(second.load_group(first_root.id()).is_err());
        assert!(second.contains_module(second_root.id()).unwrap());
    }

    #[test]
    fn release_detaches_before_finalize() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let id = context
            .insert(node("removed", finalize_module("removed", &calls)))
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
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let dependency = context
            .insert(node("dependency", finalize_module("dependency", &calls)))
            .unwrap();
        let dependency_instance = instance(&context, dependency.id());
        let lease = context
            .insert(
                node("pinned", finalize_module("pinned", &calls))
                    .dependencies([dependency_instance]),
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

    fn modules_with_pinned_binding() -> (ModuleHandle<NativeArch>, ModuleHandle<NativeArch>) {
        let provider = ModuleHandle::new(SyntheticModule::empty("provider"));
        let owner = ModuleHandle::new(SyntheticModule::empty("owner"));
        let provider_id = provider.state().instance_id();
        owner.state().install_effects([provider_id], [provider_id]);
        (provider, owner)
    }

    #[test]
    fn insert_applies_binding_pin() {
        let (provider, owner) = modules_with_pinned_binding();
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let mut leases = context
            .insert_batch([node("provider", provider), node("owner", owner)])
            .unwrap()
            .into_vec();
        let owner = leases.pop().unwrap();
        let provider = leases.pop().unwrap();

        assert!(context.release(provider).unwrap().is_empty());
        let unloaded = context.release(owner).unwrap();

        assert_eq!(unloaded.len(), 1);
        assert_eq!(unloaded[0].module().name(), "owner");
        assert!(context.module_id("provider").is_some());
    }

    #[test]
    fn import_applies_binding_pin() {
        let (provider, owner) = modules_with_pinned_binding();
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let leases = source
            .insert_batch([node("provider", provider), node("owner", owner)])
            .unwrap();
        let owner = leases[1].id();
        let mut target = LinkContext::<()>::new(DomainId::PROCESS);

        let owner = target.import(&source, owner).unwrap();
        let unloaded = target.release(owner).unwrap();

        assert_eq!(unloaded.len(), 1);
        assert_eq!(unloaded[0].module().name(), "owner");
        assert!(target.module_id("provider").is_some());
    }

    #[test]
    fn reload_invalidates_old_module_id() {
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let first = context
            .insert(node("module", SyntheticModule::empty("first")))
            .unwrap();
        let first_id = first.id();
        drop(context.release(first).unwrap());
        assert!(!context.contains_module(first_id).unwrap());
        assert_eq!(context.module_id("module"), None);

        let second = context
            .insert(node("module", SyntheticModule::empty("second")))
            .unwrap();
        assert_ne!(second.id(), first_id);
        assert_eq!(context.module_id("module"), Some(second.id()));
        let error = match context.module(first_id) {
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
        let mut first = LinkContext::<()>::new(DomainId::PROCESS);
        let mut second = LinkContext::<()>::new(DomainId::PROCESS);
        let first_id = first.insert(node("shared", module.clone())).unwrap();
        let second_id = second.insert(node("shared", module.clone())).unwrap();

        drop(first.release(first_id).unwrap());
        assert!(calls.lock().is_empty());

        drop(second.release(second_id).unwrap());
        assert!(calls.lock().is_empty());

        drop(module);
        assert_eq!(calls.lock().as_slice(), &["shared"]);
    }

    #[test]
    fn duplicate_handles_share_slot() {
        let fallback = ModuleHandle::new(SyntheticModule::empty("fallback"));
        let module = ModuleHandle::new(SyntheticModule::empty("shared"));
        let source = module.source_id();
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let fallback = context.insert(node("fallback", fallback)).unwrap();
        context.add_alias(fallback.id(), "second").unwrap();
        let first = context.insert(node("first", module.clone())).unwrap();
        let second = context.insert(node("second", module)).unwrap();

        assert_eq!(first.id(), second.id());
        assert_eq!(context.module_id("second"), Some(fallback.id()));
        let slot = context.committed.module_for_source(source).unwrap();
        assert_eq!(context.committed.make_module_id(slot), first.id());

        assert!(context.release(first).unwrap().is_empty());
        assert_eq!(context.release(fallback).unwrap().len(), 1);
        assert_eq!(context.module_id("second"), Some(second.id()));
        assert_eq!(context.release(second).unwrap().len(), 1);
    }

    #[test]
    fn module_data_outlives_context_entry() {
        let module = ModuleHandle::new(
            SyntheticModule::empty("stateful").with_user_data(String::from("module data")),
        );
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let id = context.insert(node("stateful", module.clone())).unwrap();

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
            let mut context = LinkContext::<()>::new(DomainId::PROCESS);
            let dep = context
                .insert(node("dep", finalize_module("dep", &calls)))
                .unwrap();
            let dep = instance(&context, dep.id());
            let _ = context
                .insert(node("root", finalize_module("root", &calls)).dependencies([dep]))
                .unwrap();
        }

        assert_eq!(calls.lock().as_slice(), &["root", "dep"]);
    }

    #[test]
    fn releases_all_acquisitions() {
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let id = context
            .insert(node("root", SyntheticModule::empty("root")))
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
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let shared = context
            .insert(node("shared", SyntheticModule::empty("shared")))
            .unwrap();
        let shared_instance = instance(&context, shared.id());
        let first = context
            .insert(node("first", SyntheticModule::empty("first")).dependencies([shared_instance]))
            .unwrap();
        let second = context
            .insert(
                node("second", SyntheticModule::empty("second")).dependencies([shared_instance]),
            )
            .unwrap();

        let first_id = first.id();
        let shared_id = shared.id();
        assert!(context.release(shared).unwrap().is_empty());
        let unloaded = context.release(first).unwrap();
        assert_eq!(unloaded[0].id(), first_id);
        assert!(context.contains_module(shared_id).unwrap());

        let unloaded = context.release(second).unwrap();
        assert_eq!(
            unloaded
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
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let dep = context
            .insert(node("dep", finalize_module("dep", &calls)))
            .unwrap();
        let dep_instance = instance(&context, dep.id());
        let root = context
            .insert(node("root", finalize_module("root", &calls)).dependencies([dep_instance]))
            .unwrap();

        assert!(context.release(dep).unwrap().is_empty());
        let unloaded = context.release(root).unwrap();
        drop(unloaded);

        assert_eq!(calls.lock().as_slice(), &["root", "dep"]);
    }

    #[test]
    fn alias_growth_preserves_bound_dependencies() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let canonical = context
            .insert(node("canonical", SyntheticModule::empty("canonical")))
            .expect("failed to insert canonical module");
        let canonical_id = canonical.id();
        context
            .add_alias(canonical_id, "alias")
            .expect("failed to add alias");
        let canonical_instance = instance(&context, canonical_id);
        let root = context
            .insert(node("root", SyntheticModule::empty("root")).dependencies([canonical_instance]))
            .expect("failed to insert root module");
        let root_id = root.id();
        let replacement = context
            .insert(node("replacement", SyntheticModule::empty("replacement")))
            .expect("failed to insert replacement module");
        let replacement_id = replacement.id();
        context
            .add_alias(replacement_id, "alias")
            .expect("failed to add alias fallback");

        assert_eq!(context.module_id("alias"), Some(canonical_id));
        assert_eq!(direct_deps(&context, root_id), [canonical_id]);
        assert_eq!(
            load_group_names(&mut context, root_id),
            ["root", "canonical"]
        );
    }

    #[test]
    fn alias_uses_registration_order() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let first = context
            .insert(node("first", SyntheticModule::empty("first")))
            .expect("failed to insert first module");
        let second = context
            .insert(node("second", SyntheticModule::empty("second")))
            .expect("failed to insert second module");
        let first_id = first.id();
        let second_id = second.id();

        context
            .add_alias(first_id, "alias")
            .expect("failed to add alias");
        assert_eq!(context.module_id("alias"), Some(first_id));
        context
            .add_alias(second_id, "alias")
            .expect("failed to add alias fallback");
        context
            .add_alias(second_id, "alias")
            .expect("failed to keep alias fallback");
        assert_eq!(context.module_id("alias"), Some(first_id));

        assert_eq!(context.release(first).unwrap().len(), 1);
        assert_eq!(context.module_id("alias"), Some(second_id));
        assert_eq!(context.release(second).unwrap().len(), 1);
        assert_eq!(context.module_id("alias"), None);
    }

    #[test]
    fn load_order_tracks_reused_slots() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let first = context
            .insert(node("first", SyntheticModule::empty("first")))
            .unwrap();
        let second = context
            .insert(node("second", SyntheticModule::empty("second")))
            .unwrap();

        drop(context.release(first).unwrap());
        let first = context
            .insert(node("first", SyntheticModule::empty("first")))
            .unwrap();
        let names = context
            .load_order()
            .map(|id| context.module(id).unwrap().name())
            .collect::<Vec<_>>();
        assert_eq!(names, ["second", "first"]);

        drop(context.release(second).unwrap());
        drop(context.release(first).unwrap());
    }

    #[test]
    fn duplicate_keys_preserve_insertion_order() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let first = context
            .insert(node("root", SyntheticModule::empty("old-root")))
            .expect("failed to insert root module");
        let first_id = first.id();
        let second = context
            .insert(node("root", SyntheticModule::empty("new-root")))
            .expect("failed to insert fallback module");

        assert_eq!(context.module_id("root"), Some(first_id));
        assert_eq!(context.release(first).unwrap().len(), 1);
        assert_eq!(context.module_id("root"), Some(second.id()));
        assert_eq!(context.release(second).unwrap().len(), 1);
    }

    #[test]
    fn keys_use_registration_order() {
        let mut context = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let root = context
            .insert(node("root", SyntheticModule::empty("root")))
            .expect("failed to insert root module");
        let root_id = root.id();
        context
            .add_alias(root_id, "alias")
            .expect("failed to add alias");
        let dep_module = context
            .insert(node("dep", SyntheticModule::empty("dep")))
            .expect("failed to insert dependency");
        let dep_module_id = dep_module.id();
        let dep_instance = instance(&context, dep_module_id);

        let fallback = context
            .insert(node("alias", SyntheticModule::empty("alias")).dependencies([dep_instance]))
            .expect("failed to insert fallback module");
        assert_ne!(fallback.id(), root_id);
        assert_eq!(context.module_id("alias"), Some(root_id));
        assert_eq!(context.module_key(root_id).unwrap().as_str(), "root");
        assert_eq!(context.module_key(fallback.id()).unwrap().as_str(), "alias");
        assert_eq!(direct_deps(&context, fallback.id()), [dep_module_id]);

        assert_eq!(context.release(root).unwrap().len(), 1);
        assert_eq!(context.module_id("alias"), Some(fallback.id()));
        assert_eq!(context.release(fallback).unwrap().len(), 1);
        assert_eq!(context.release(dep_module).unwrap().len(), 1);
    }

    #[test]
    fn import_roots_preserves_bound_dependencies() {
        let mut source = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
        let canonical = source
            .insert(node("canonical", SyntheticModule::empty("canonical")))
            .expect("failed to insert canonical module");
        let canonical_id = canonical.id();
        source
            .add_alias(canonical_id, "alias")
            .expect("failed to add alias");
        let canonical_instance = instance(&source, canonical_id);
        let root = source
            .insert(node("root", SyntheticModule::empty("root")).dependencies([canonical_instance]))
            .expect("failed to insert root module");
        let root_id = root.id();
        let replacement = source
            .insert(node("replacement", SyntheticModule::empty("replacement")))
            .expect("failed to insert replacement module");
        source
            .add_alias(replacement.id(), "alias")
            .expect("failed to add alias fallback");

        let mut target = LinkContext::<(), NativeArch>::new(DomainId::PROCESS);
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
            load_group_names(&mut source, root_id),
            ["root", "canonical"]
        );
        assert_eq!(direct_deps(&target, target_root), [target_canonical]);
        assert_eq!(target.module_id("alias"), None);
        assert!(target.contains_module(target_replacement).unwrap());
        assert_eq!(
            load_group_names(&mut target, target_root),
            ["root", "canonical"]
        );
    }

    #[test]
    fn imported_modules_have_context_local_metadata() {
        let mut source = LinkContext::<usize>::new(DomainId::PROCESS);
        let source_lease = source
            .insert(GraphModule::with_meta(
                "module",
                SyntheticModule::empty("module"),
                7,
            ))
            .unwrap();
        let source_id = source_lease.id();

        let mut target = LinkContext::<String>::new(DomainId::PROCESS);
        let target_lease = target.import(&source, source_id).unwrap();
        let target_id = target_lease.id();

        assert!(
            source
                .module(source_id)
                .unwrap()
                .ptr_eq(target.module(target_id).unwrap())
        );
        assert_eq!(source.meta(source_id).unwrap(), &7);
        assert_eq!(target.meta(target_id).unwrap(), "");
        target.meta_mut(target_id).unwrap().push_str("target");
        assert_eq!(source.meta(source_id).unwrap(), &7);

        let target_unload = target.release(target_lease).unwrap();
        assert_eq!(target_unload[0].meta(), "target");
        let source_unload = source.release(source_lease).unwrap();
        assert_eq!(*source_unload[0].meta(), 7);
    }

    #[test]
    fn import_copies_only_dependency_closure() {
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let source_dep = source
            .insert(node("dep", SyntheticModule::empty("dep")))
            .unwrap();
        let source_dep_instance = instance(&source, source_dep.id());
        let source_root = source
            .insert(
                node("root", SyntheticModule::empty("root")).dependencies([source_dep_instance]),
            )
            .unwrap();
        let source_dep_id = source_dep.id();
        let source_root_id = source_root.id();
        let _ = source
            .insert(node("unrelated", SyntheticModule::empty("unrelated")))
            .unwrap();

        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
        let root = target.import(&source, source_root_id).unwrap();
        let root_id = root.id();
        let dep = target
            .module_id("dep")
            .expect("dependency should be imported");

        assert!(target.module_id("unrelated").is_none());
        assert!(
            target
                .module(root_id)
                .unwrap()
                .ptr_eq(source.module(source_root_id).unwrap())
        );
        assert!(
            target
                .module(dep)
                .unwrap()
                .ptr_eq(source.module(source_dep_id).unwrap())
        );
        assert_eq!(load_group_names(&mut target, root_id), ["root", "dep"]);

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
    fn import_preserves_conflicting_key_order() {
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let dep = source
            .insert(node("dep", SyntheticModule::empty("dep")))
            .unwrap();
        let dep_instance = instance(&source, dep.id());
        let source_root = source
            .insert(
                node("root", SyntheticModule::empty("source-root")).dependencies([dep_instance]),
            )
            .unwrap();

        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
        let existing = target
            .insert(node("root", SyntheticModule::empty("target-root")))
            .unwrap();
        let existing_id = existing.id();
        let imported = target.import(&source, source_root.id()).unwrap();

        assert_ne!(imported.id(), existing_id);
        assert_eq!(target.module_id("root"), Some(existing_id));
        assert!(target.module_id("dep").is_some());
        assert_eq!(target.release(existing).unwrap().len(), 1);
        assert_eq!(target.module_id("root"), Some(imported.id()));
        assert_eq!(target.release(imported).unwrap().len(), 2);
    }

    #[test]
    fn import_uses_entry_key() {
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let source_root = source
            .insert(node("canonical", SyntheticModule::empty("canonical")))
            .unwrap();
        source.add_alias(source_root.id(), "alias").unwrap();

        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
        let imported = target.import(&source, source_root.id()).unwrap();

        assert_eq!(
            target.module_key(imported.id()).unwrap().as_str(),
            "canonical"
        );
        assert!(target.module_id("canonical").is_some());
        assert!(target.module_id("alias").is_none());
    }

    #[test]
    fn import_reuses_shared_handle() {
        let module = ModuleHandle::new(SyntheticModule::empty("shared"));
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let source_lease = source.insert(node("source", module.clone())).unwrap();
        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
        let target_lease = target.insert(node("target", module)).unwrap();

        let imported = target.import(&source, source_lease.id()).unwrap();
        assert_eq!(imported.id(), target_lease.id());
        assert_eq!(target.module_id("source"), Some(target_lease.id()));
        assert_eq!(target.load_order().count(), 1);

        assert!(target.release(imported).unwrap().is_empty());
        assert_eq!(target.release(target_lease).unwrap().len(), 1);
    }

    #[test]
    fn import_does_not_follow_target_alias() {
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let source_root = source
            .insert(node("source", SyntheticModule::empty("source")))
            .unwrap();
        source.add_alias(source_root.id(), "alias").unwrap();

        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
        let existing = target
            .insert(node("target", SyntheticModule::empty("target")))
            .unwrap();
        let existing_id = existing.id();
        target.add_alias(existing_id, "alias").unwrap();
        let imported = target.import(&source, source_root.id()).unwrap();

        assert_ne!(imported.id(), existing_id);
        assert!(target.module_id("source").is_some());
        assert_eq!(target.module_id("alias"), Some(existing_id));
    }

    #[test]
    fn import_roots_preserves_lifecycle() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let dep = source
            .insert(node("dep", finalize_module("dep", &calls)))
            .unwrap();
        let dep_instance = instance(&source, dep.id());
        let _ = source
            .insert(node("root", finalize_module("root", &calls)).dependencies([dep_instance]))
            .unwrap();
        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
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
        let mut source = LinkContext::<()>::new(DomainId::PROCESS);
        let source_root = source
            .insert(node("root", SyntheticModule::empty("root")))
            .unwrap();
        let source_root_id = source_root.id();
        let _second = source.acquire(source_root_id).unwrap();

        let mut target = LinkContext::<()>::new(DomainId::PROCESS);
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
