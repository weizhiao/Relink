use super::storage::{
    CommittedStorage, ContextId, LeaseError, ModuleId, ModuleKey, ModuleLease, ModuleSlot,
};
use super::unload::UnloadGroup;
use crate::{
    Result,
    arch::NativeArch,
    entity::EntitySet,
    image::{GlobalScope, Module, ModuleScope, SearchPathPool},
    linker::{AddressIndex, AddressMatch},
    memory::VmAddr,
    relocation::{RelocationArch, SymbolRegistry},
    runtime::{AddressSpaceId, Domain, DomainId},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{collections::VecDeque, vec::Vec};

/// A symbol namespace containing loaded modules and their dependencies.
///
/// Used with [`crate::Linker`]. All modules must match the context's fixed domain.
/// Contexts can share a domain while keeping independent module IDs, dependency
/// graphs, and GNU unique symbol definitions.
///
/// `Meta` belongs to each context entry and is created separately on import.
/// Store data that must follow the shared module in the module itself.
pub struct LinkContext<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    pub(super) domain: Domain<Arch, Tls>,
    pub(super) global: GlobalScope<Arch>,
    pub(super) committed: CommittedStorage<Meta, Arch>,
    pub(super) symbols: Arc<SymbolRegistry<Arch>>,
    pub(crate) search_paths: SearchPathPool,
}

impl LinkContext<(), NativeArch, ()> {
    /// Creates an empty namespace targeting the current native process.
    ///
    /// Use [`new`](Self::new) when the namespace needs custom metadata, an
    /// explicit target architecture or TLS resolver, or another runtime domain.
    #[inline]
    pub fn for_process() -> Self {
        Self::new(Domain::native(AddressSpaceId::PROCESS))
    }
}

impl<Meta, Arch, Tls> LinkContext<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates an empty link context bound to a fixed runtime domain.
    pub fn new(domain: Domain<Arch, Tls>) -> Self {
        Self {
            global: GlobalScope::new(domain.id()),
            committed: CommittedStorage::new(ContextId::fresh(), domain.id()),
            domain,
            symbols: Arc::new(SymbolRegistry::new()),
            search_paths: SearchPathPool::default(),
        }
    }

    /// Returns the fixed domain used by this context and all its loader runs.
    pub fn domain(&self) -> &Domain<Arch, Tls> {
        &self.domain
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
    pub const fn global_scope(&self) -> &GlobalScope<Arch> {
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

    /// Returns this context's directory pool and dynamic path-token settings.
    #[inline]
    pub fn search_paths(&self) -> &SearchPathPool {
        &self.search_paths
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
    pub fn module_id(&self, key: impl AsRef<[u8]>) -> Option<ModuleId> {
        self.committed
            .module_for_key(key)
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Returns the committed module id for this exact loaded module instance.
    ///
    /// A different instance loaded from the same source does not match.
    #[inline]
    pub fn module_id_for(&self, module: &dyn Module<Arch>) -> Option<ModuleId> {
        self.committed
            .module_for_binding(module.state().instance_id())
            .map(|slot| self.committed.make_module_id(slot))
    }

    /// Finds the committed mapping containing `addr`.
    pub fn address_at(&self, addr: VmAddr) -> Option<AddressMatch> {
        self.committed
            .addresses
            .find(addr)
            .map(|(owner, range)| AddressMatch { owner, range })
    }

    /// Retains a read-only address index for the current committed modules.
    ///
    /// Later commits and removals use copy-on-write. This snapshot does not keep
    /// modules or mappings alive: the caller must retain their owners while
    /// querying it.
    pub fn address_index(&self) -> Arc<AddressIndex> {
        self.committed.addresses.clone()
    }

    /// Returns the representative key associated with a committed module id.
    #[inline]
    pub fn module_key(&self, id: ModuleId) -> Result<&ModuleKey> {
        Ok(self.committed.checked_module(id)?.entry_key())
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
    pub fn module(&self, id: ModuleId) -> Result<&dyn Module<Arch>> {
        Ok(self.committed.checked_module(id)?.handle().as_ref())
    }

    /// Returns metadata owned by this context entry.
    #[inline]
    pub fn meta(&self, id: ModuleId) -> Result<&Meta> {
        Ok(self.committed.checked_module(id)?.meta())
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

    /// Returns the live module that first introduced `id` as a dependency in this context.
    ///
    /// A newly loaded root or manually inserted module returns `None`. Reusing a
    /// module preserves its original loader. Unloading that loader clears the
    /// relationship. When copying modules on import, both ends of the relationship
    /// must belong to the imported closure.
    #[inline]
    pub fn module_loader(&self, id: ModuleId) -> Result<Option<ModuleId>> {
        Ok(self
            .committed
            .checked_module(id)?
            .loader()
            .map(|slot| self.committed.make_module_id(slot)))
    }

    /// Returns direct dependency modules for a committed module.
    #[inline]
    pub fn direct_deps(&self, id: ModuleId) -> Result<impl Iterator<Item = ModuleId> + '_> {
        Ok(self
            .committed
            .checked_module(id)?
            .direct_deps()
            .iter()
            .copied()
            .map(|slot| self.committed.make_module_id(slot)))
    }

    /// Returns modules retained by this module's runtime symbol bindings.
    #[inline]
    pub fn reloc_deps(&self, id: ModuleId) -> Result<impl Iterator<Item = ModuleId> + '_> {
        let deps = self
            .committed
            .checked_module(id)?
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

    fn lease_slot(&self, lease: ModuleLease) -> core::result::Result<ModuleSlot, LeaseError> {
        self.committed
            .module_slot(lease.id())
            .map_err(|error| LeaseError {
                error,
                acquisition: lease,
            })
    }

    /// Converts one direct acquisition into a permanent context root.
    ///
    /// A pinned module and its dependency closure remain committed until the
    /// context itself is dropped. Pinning an already pinned module is
    /// idempotent, but still consumes the supplied acquisition.
    /// A rejected lease is returned in [`LeaseError::acquisition`].
    pub fn pin(&mut self, lease: ModuleLease) -> core::result::Result<(), LeaseError> {
        let slot = self.lease_slot(lease)?;
        let mut module = self
            .committed
            .module_mut(slot)
            .expect("validated module id must refer to committed state");
        module.release_root();
        module.pin();
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
                global.push_admitted(module.handle().clone());
            }
            queue.extend(module.direct_deps().iter().copied());
        }
        Ok(())
    }

    /// Appends modules to global lookup order without traversing their dependencies.
    /// Leases, pins, and dependency reachability still control module lifetime.
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
                global.push_admitted(module.handle().clone());
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
    /// A rejected lease is returned in [`LeaseError::acquisition`].
    pub fn release(
        &mut self,
        lease: ModuleLease,
    ) -> core::result::Result<UnloadGroup<Meta, Arch>, LeaseError> {
        self.release_with_pins(lease, &[])
    }

    pub(super) fn release_with_pins(
        &mut self,
        lease: ModuleLease,
        pins: &[ModuleSlot],
    ) -> core::result::Result<UnloadGroup<Meta, Arch>, LeaseError> {
        let slot = self.lease_slot(lease)?;
        for &pin in pins {
            self.committed
                .module_mut(pin)
                .expect("published pin must remain committed until rollback")
                .unpin();
        }
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

        // The traversal exhausted this buffer; reuse it for reverse unload order.
        pending.extend(
            self.committed
                .lifecycle()
                .rev()
                .filter(|slot| !reachable.contains(*slot)),
        );
        global.retain(|module| {
            self.committed
                .module_for_source(module.source_id())
                .is_some_and(|slot| reachable.contains(slot))
        });
        Ok(self.committed.remove_batch(pending, &reachable))
    }

    /// Returns the retained breadth-first dependency scope rooted at `root`.
    pub fn load_group(&mut self, root: ModuleId) -> Result<ModuleScope<Arch>> {
        let root_slot = self.committed.module_slot(root)?;
        let root_module = self
            .committed
            .module(root_slot)
            .expect("validated module id must refer to committed state");
        if let Some(scope) = root_module.load_group() {
            return Ok(scope.clone());
        }

        let mut scope = Vec::new();
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

        let scope = ModuleScope::from_admitted(self.domain.id(), scope);
        self.committed
            .module_mut(root_slot)
            .expect("validated module id must refer to committed state")
            .cache_load_group(scope.clone());
        Ok(scope)
    }
}
