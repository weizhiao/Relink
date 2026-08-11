use super::{
    context::LinkContext,
    storage::{CommittedStorage, KeySlot, ModuleGuard, ModuleId, ModuleSlot, StoredEntry},
};
use crate::{
    LinkContextError, LinkerError, Result,
    entity::{EntitySet, SecondaryMap},
    image::{LoadedCore, LookupScope, ModuleHandle, ModuleIdentity, ModuleScope, RawDynamic},
    input::FileId,
    memory::RegionAccess,
    relocation::RelocationArch,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

pub(crate) struct GraphEntry<P> {
    payload: P,
    loader: Option<ModuleSlot>,
    direct_deps: Option<Box<[ModuleSlot]>>,
}

impl<P> GraphEntry<P> {
    #[inline]
    pub(crate) fn payload(&self) -> &P {
        &self.payload
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> Option<&[ModuleSlot]> {
        self.direct_deps.as_deref()
    }

    #[inline]
    pub(crate) const fn loader(&self) -> Option<ModuleSlot> {
        self.loader
    }

    #[inline]
    pub(crate) fn set_direct_deps(&mut self, direct_deps: Vec<ModuleSlot>) {
        self.direct_deps = Some(direct_deps.into_boxed_slice());
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (P, Option<Box<[ModuleSlot]>>) {
        (self.payload, self.direct_deps)
    }
}

pub(crate) struct PendingModule<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[ModuleSlot]>,
    scope: Option<LookupScope<Arch, Tls>>,
    bindings: Box<[PendingBinding]>,
}

struct PendingBinding {
    slot: ModuleSlot,
    pin: bool,
}

impl<Arch, Tls> PendingModule<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(module: ModuleHandle<Arch, Tls>, direct_deps: Box<[ModuleSlot]>) -> Self {
        Self {
            module,
            direct_deps,
            scope: None,
            bindings: Box::new([]),
        }
    }

    #[inline]
    pub(crate) fn module(&self) -> &ModuleHandle<Arch, Tls> {
        &self.module
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> &[ModuleSlot] {
        &self.direct_deps
    }
}

pub(crate) struct ResolveSession<P, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    dynamics: BTreeMap<ModuleSlot, GraphEntry<P>>,
    modules: BTreeMap<ModuleSlot, PendingModule<Arch, Tls>>,
    guards: Vec<ModuleGuard>,
    group_order: Vec<ModuleSlot>,
    aliases: SecondaryMap<KeySlot, Vec<ModuleSlot>>,
    files: BTreeMap<FileId, ModuleSlot>,
    identities: BTreeMap<ModuleIdentity, ModuleGuard>,
}

pub(crate) struct ModuleIndex {
    committed: Arc<BTreeMap<ModuleIdentity, ModuleGuard>>,
    pending: BTreeMap<ModuleIdentity, ModuleGuard>,
}

impl ModuleIndex {
    #[inline]
    pub(crate) fn new(
        committed: Arc<BTreeMap<ModuleIdentity, ModuleGuard>>,
        pending: BTreeMap<ModuleIdentity, ModuleGuard>,
    ) -> Self {
        assert!(
            pending
                .keys()
                .all(|identity| !committed.contains_key(identity)),
            "pending module identity must not already be committed"
        );
        Self { committed, pending }
    }

    #[inline]
    fn get(&self, identity: ModuleIdentity) -> Option<ModuleGuard> {
        self.committed
            .get(&identity)
            .or_else(|| self.pending.get(&identity))
            .copied()
    }
}

impl<P, Arch, Tls> ResolveSession<P, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            dynamics: BTreeMap::new(),
            modules: BTreeMap::new(),
            guards: Vec::new(),
            group_order: Vec::new(),
            aliases: SecondaryMap::new(),
            files: BTreeMap::new(),
            identities: BTreeMap::new(),
        }
    }

    #[inline]
    pub(crate) fn contains_pending(&self, slot: ModuleSlot) -> bool {
        self.dynamics.contains_key(&slot) || self.modules.contains_key(&slot)
    }

    #[inline]
    pub(crate) fn pending_is_empty(&self) -> bool {
        self.dynamics.is_empty() && self.modules.is_empty()
    }

    #[inline]
    pub(crate) fn alias_module(&self, alias: KeySlot) -> Option<ModuleSlot> {
        self.aliases
            .get(alias)
            .and_then(|modules| modules.first().copied())
    }

    #[inline]
    pub(crate) fn stage_alias(&mut self, alias: KeySlot, module: ModuleSlot) {
        let modules = self.aliases.get_or_default(alias);
        if !modules.contains(&module) {
            modules.push(module);
        }
    }

    #[inline]
    pub(crate) fn file_module(&self, id: FileId) -> Option<ModuleSlot> {
        self.files.get(&id).copied()
    }

    #[inline]
    pub(crate) fn matching_module(&self, module: &ModuleHandle<Arch, Tls>) -> Option<ModuleSlot> {
        self.identities
            .get(&module.identity())
            .map(|guard| guard.slot)
            .or_else(|| {
                module
                    .search()
                    .and_then(|search| search.file_id())
                    .and_then(|id| self.files.get(&id).copied())
            })
    }

    #[inline]
    pub(crate) fn stage_file(&mut self, id: Option<FileId>, module: ModuleSlot) {
        if let Some(id) = id {
            assert!(
                !self.files.contains_key(&id),
                "pending module file identities must be unique"
            );
            let previous = self.files.insert(id, module);
            debug_assert!(previous.is_none());
        }
    }

    #[inline]
    pub(crate) fn direct_deps(&self, slot: ModuleSlot) -> Option<&[ModuleSlot]> {
        self.dynamics
            .get(&slot)
            .and_then(GraphEntry::direct_deps)
            .or_else(|| self.modules.get(&slot).map(PendingModule::direct_deps))
    }

    #[inline]
    pub(crate) fn dynamic_payload(&self, slot: ModuleSlot) -> Option<&P> {
        self.dynamics.get(&slot).map(GraphEntry::payload)
    }

    #[inline]
    pub(crate) fn loader(&self, slot: ModuleSlot) -> Option<ModuleSlot> {
        self.dynamics.get(&slot).and_then(GraphEntry::loader)
    }

    pub(crate) fn set_direct_deps(&mut self, slot: ModuleSlot, direct_deps: Vec<ModuleSlot>) {
        self.dynamics
            .get_mut(&slot)
            .expect("session entry must exist for staged key")
            .set_direct_deps(direct_deps);
    }

    pub(crate) fn stage_dynamic(
        &mut self,
        slot: ModuleSlot,
        generation: u32,
        payload: P,
        loader: Option<ModuleSlot>,
    ) {
        self.track(slot, generation);
        let previous = self.dynamics.insert(
            slot,
            GraphEntry {
                payload,
                loader,
                direct_deps: None,
            },
        );
        debug_assert!(previous.is_none(), "pending dynamic modules must be unique");
    }

    pub(crate) fn stage_module(
        &mut self,
        slot: ModuleSlot,
        generation: u32,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
    ) {
        self.track(slot, generation);
        let identity = module.identity();
        let previous = self
            .modules
            .insert(slot, PendingModule::new(module, direct_deps));
        debug_assert!(previous.is_none(), "pending modules must be unique");
        let previous = self
            .identities
            .insert(identity, ModuleGuard { slot, generation });
        assert!(
            previous.is_none(),
            "pending module identities must be unique"
        );
    }

    pub(crate) fn split_dynamics<Q>(
        self,
    ) -> (
        BTreeMap<ModuleSlot, GraphEntry<P>>,
        ResolveSession<Q, Arch, Tls>,
    ) {
        let Self {
            dynamics,
            modules,
            guards,
            group_order,
            aliases,
            files,
            identities,
        } = self;
        (
            dynamics,
            ResolveSession {
                dynamics: BTreeMap::new(),
                modules,
                guards,
                group_order,
                aliases,
                files,
                identities,
            },
        )
    }

    pub(crate) fn restore_dynamic(
        &mut self,
        slot: ModuleSlot,
        payload: P,
        direct_deps: Box<[ModuleSlot]>,
    ) {
        let previous = self.dynamics.insert(
            slot,
            GraphEntry {
                payload,
                loader: None,
                direct_deps: Some(direct_deps),
            },
        );
        debug_assert!(
            previous.is_none(),
            "restored dynamic modules must be unique"
        );
    }

    #[inline]
    pub(crate) fn group_order(&self) -> &[ModuleSlot] {
        &self.group_order
    }

    #[inline]
    pub(crate) fn set_group_order(&mut self, order: Vec<ModuleSlot>) {
        self.group_order = order;
    }

    #[inline]
    pub(crate) fn track(&mut self, slot: ModuleSlot, generation: u32) {
        if let Some(guard) = self.guards.iter().find(|guard| guard.slot == slot) {
            debug_assert_eq!(guard.generation, generation);
            return;
        }
        self.guards.push(ModuleGuard { slot, generation });
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn build_scope<K, Meta>(
        &mut self,
        context: &LinkContext<K, Meta, Arch, Tls>,
    ) -> (
        ModuleScope<Arch, Tls>,
        BTreeMap<ModuleIdentity, ModuleGuard>,
    ) {
        let mut scope = ModuleScope::new(context.domain_id());
        for &id in &self.group_order {
            let dynamic = self.dynamics.contains_key(&id);
            let module = if let Some(raw) = self.dynamics.get(&id).map(GraphEntry::payload) {
                let module = unsafe { LoadedCore::from_core(raw.core()) };
                ModuleHandle::from(module)
            } else if let Some(module) = self.modules.get(&id).map(PendingModule::module) {
                module.clone()
            } else {
                context
                    .committed
                    .module(id)
                    .map(|module| module.handle().clone())
                    .expect("scope slot must resolve to a committed module")
            };
            if dynamic {
                let previous = self.identities.insert(
                    module.identity(),
                    ModuleGuard {
                        slot: id,
                        generation: context.committed.generation(id),
                    },
                );
                assert!(
                    previous.is_none(),
                    "pending module identities must be unique"
                );
            }
            scope.push(module);
        }
        (scope, core::mem::take(&mut self.identities))
    }
}

pub(crate) struct LoadSession<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    resolve: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>,
    ready_to_commit: BTreeMap<ModuleSlot, PendingModule<Arch, Tls>>,
    lifecycle: Vec<ModuleSlot>,
}

impl<D: Send + Sync + 'static, Arch, R, Tls> LoadSession<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn from_resolve(
        resolve: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>,
    ) -> Self {
        Self {
            resolve,
            ready_to_commit: BTreeMap::new(),
            lifecycle: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn take_pending_dynamic(
        &mut self,
        slot: ModuleSlot,
    ) -> Option<GraphEntry<RawDynamic<D, Arch, R, Tls>>> {
        self.resolve.dynamics.remove(&slot)
    }

    #[inline]
    pub(crate) fn push_ready(
        &mut self,
        slot: ModuleSlot,
        loaded: LoadedCore<D, Arch, R, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        slots: &ModuleIndex,
    ) {
        let (module, scope, bindings) = loaded.into_context_parts();
        let bindings = bindings.into_bindings(&scope);
        let mut pending = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let (module, pin) = binding.into_parts();
            let Some(guard) = slots.get(module.identity()) else {
                continue;
            };
            self.resolve.track(guard.slot, guard.generation);
            pending.push(PendingBinding {
                slot: guard.slot,
                pin,
            });
        }
        let previous = self.ready_to_commit.insert(
            slot,
            PendingModule {
                module,
                direct_deps,
                scope: Some(scope),
                bindings: pending.into_boxed_slice(),
            },
        );
        debug_assert!(previous.is_none(), "ready commit entries must be unique");
    }

    #[inline]
    pub(crate) fn push_lifecycle(&mut self, slot: ModuleSlot) {
        self.lifecycle.push(slot);
    }

    pub(crate) fn mark_module_ready(&mut self, slot: ModuleSlot) {
        let module = self
            .resolve
            .modules
            .remove(&slot)
            .expect("missing pending module handle while preparing lifecycle");
        let previous = self.ready_to_commit.insert(slot, module);
        debug_assert!(previous.is_none(), "ready commit entries must be unique");
    }

    pub(crate) fn initializers(&self) -> Vec<ModuleHandle<Arch, Tls>> {
        self.lifecycle
            .iter()
            .map(|id| {
                let module = self
                    .ready_to_commit
                    .get(id)
                    .expect("lifecycle order must refer to a ready module");
                module.module.clone()
            })
            .collect()
    }

    pub(crate) fn build_lifecycle_order(&self, root: ModuleSlot, order: &mut Vec<ModuleSlot>) {
        order.clear();
        let pending_len = self.resolve.dynamics.len() + self.resolve.modules.len();
        if order.capacity() < pending_len {
            order.reserve(pending_len - order.capacity());
        }

        let mut visited = EntitySet::default();
        let mut stack = Vec::with_capacity(pending_len.saturating_mul(2));
        stack.push((root, false));

        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                if self.resolve.contains_pending(id) {
                    order.push(id);
                }
                continue;
            }

            if !visited.insert(id) {
                continue;
            }

            let direct_deps = self
                .resolve
                .dynamics
                .get(&id)
                .and_then(GraphEntry::direct_deps)
                .or_else(|| {
                    self.resolve
                        .modules
                        .get(&id)
                        .map(PendingModule::direct_deps)
                });
            let Some(direct_deps) = direct_deps else {
                continue;
            };

            stack.push((id, true));
            for &dep in direct_deps.iter().rev() {
                stack.push((dep, false));
            }
        }
    }

    pub(crate) fn commit_into<K, Meta>(
        self,
        committed: &mut CommittedStorage<K, Meta, Arch, Tls>,
    ) -> Result<CommitResult>
    where
        K: Clone + Ord,
        Meta: Default,
    {
        let Self {
            resolve,
            ready_to_commit,
            lifecycle,
        } = self;
        let ResolveSession {
            guards,
            group_order,
            aliases,
            ..
        } = resolve;
        let mut ready = ready_to_commit;
        let mut committed_ids = Vec::with_capacity(ready.len());
        for ModuleGuard { slot, generation } in guards {
            if committed.generation(slot) != generation {
                return Err(LinkerError::context(LinkContextError::ModuleChanged {
                    id: ModuleId::from_slot(committed.context(), slot, generation),
                })
                .into());
            }
        }
        let mut requested_pins = Vec::new();
        for slot in group_order {
            let Some(entry) = ready.remove(&slot) else {
                continue;
            };
            let PendingModule {
                module,
                direct_deps,
                scope,
                bindings,
            } = entry;
            let mut reloc_deps = Vec::with_capacity(bindings.len());
            for binding in bindings {
                if binding.slot != slot && !direct_deps.contains(&binding.slot) {
                    reloc_deps.push(binding.slot);
                }
                if binding.pin {
                    requested_pins.push(binding.slot);
                }
            }
            committed.insert(
                slot,
                StoredEntry::relocated(
                    module,
                    direct_deps,
                    reloc_deps.into_boxed_slice(),
                    scope,
                    0,
                    Meta::default(),
                ),
            );
            committed_ids.push(committed.make_module_id(slot));
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        for (alias, modules) in aliases.iter() {
            for &module in modules {
                committed.add_alias(alias, module);
            }
        }
        committed.extend_lifecycle(&lifecycle);
        let mut pins = Vec::new();
        for slot in requested_pins {
            let newly_pinned = committed
                .module_mut(slot)
                .is_some_and(|mut module| module.pin());
            if newly_pinned {
                pins.push(committed.make_module_id(slot));
            }
        }
        Ok(CommitResult {
            modules: committed_ids.into_boxed_slice(),
            pins: pins.into_boxed_slice(),
        })
    }
}

pub(crate) struct CommitResult {
    pub(crate) modules: Box<[ModuleId]>,
    pub(crate) pins: Box<[ModuleId]>,
}
