use super::{
    context::LinkContext,
    storage::{CommittedStorage, KeySlot, ModuleId, ModuleSlot, StoredEntry},
};
use crate::{
    LinkContextError, LinkerError, Result,
    entity::{EntitySet, SecondaryMap},
    image::{LoadedCore, LookupScope, ModuleHandle, ModuleScope, RawDynamic},
    input::ModuleSourceId,
    memory::RegionAccess,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    vec::Vec,
};

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
    scope: LookupScope<Arch, Tls>,
}

impl<Arch, Tls> PendingModule<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(module: ModuleHandle<Arch, Tls>, direct_deps: Box<[ModuleSlot]>) -> Self {
        let scope = LookupScope::empty(module.domain_id());
        Self {
            module,
            direct_deps,
            scope,
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
    // Generations observed while resolving. Publication rejects the whole
    // transaction if any referenced slot changed before commit.
    guards: BTreeMap<ModuleSlot, u32>,
    group_order: Vec<ModuleSlot>,
    bindings: SecondaryMap<KeySlot, Vec<ModuleSlot>>,
    sources: BTreeMap<ModuleSourceId, ModuleSlot>,
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
            guards: BTreeMap::new(),
            group_order: Vec::new(),
            bindings: SecondaryMap::new(),
            sources: BTreeMap::new(),
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
    pub(crate) fn module_for_key(&self, key: KeySlot) -> Option<ModuleSlot> {
        self.bindings
            .get(key)
            .and_then(|modules| modules.first().copied())
    }

    #[inline]
    pub(crate) fn bind_key(&mut self, key: KeySlot, module: ModuleSlot) {
        let modules = self.bindings.get_or_default(key);
        if !modules.contains(&module) {
            modules.push(module);
        }
    }

    #[inline]
    pub(crate) fn module_for_source(&self, id: ModuleSourceId) -> Option<ModuleSlot> {
        self.sources.get(&id).copied()
    }

    #[inline]
    pub(crate) fn stage_source(&mut self, id: ModuleSourceId, module: ModuleSlot) {
        if let Some(previous) = self.sources.insert(id, module) {
            assert_eq!(previous, module, "pending module sources must be unique");
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
        let source = module.source_id();
        let previous = self
            .modules
            .insert(slot, PendingModule::new(module, direct_deps));
        debug_assert!(previous.is_none(), "pending modules must be unique");
        self.stage_source(source, slot);
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
            bindings,
            sources,
        } = self;
        (
            dynamics,
            ResolveSession {
                dynamics: BTreeMap::new(),
                modules,
                guards,
                group_order,
                bindings,
                sources,
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
        match self.guards.entry(slot) {
            Entry::Vacant(entry) => {
                entry.insert(generation);
            }
            Entry::Occupied(entry) => debug_assert_eq!(*entry.get(), generation),
        }
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn build_scope<Meta>(
        &self,
        context: &LinkContext<Meta, Arch, Tls>,
    ) -> ModuleScope<Arch, Tls> {
        let mut scope = ModuleScope::new(context.domain_id());
        for index in 0..self.group_order.len() {
            let id = self.group_order[index];
            let module = if let Some(raw) = self.dynamics.get(&id).map(GraphEntry::payload) {
                raw.module_handle()
            } else if let Some(module) = self.modules.get(&id).map(PendingModule::module) {
                module.clone()
            } else {
                context
                    .committed
                    .module(id)
                    .map(|module| module.handle().clone())
                    .expect("scope slot must resolve to a committed module")
            };
            scope.push(module);
        }
        scope
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

pub(crate) struct PublishSession<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    guards: BTreeMap<ModuleSlot, u32>,
    modules: BTreeMap<ModuleSlot, PendingModule<Arch, Tls>>,
    order: Vec<ModuleSlot>,
    bindings: SecondaryMap<KeySlot, Vec<ModuleSlot>>,
    pending_sources: BTreeMap<ModuleSourceId, ModuleSlot>,
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
    ) {
        let (module, scope) = loaded.into_context_parts();
        let previous = self.ready_to_commit.insert(
            slot,
            PendingModule {
                module,
                direct_deps,
                scope,
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

    pub(crate) fn into_publish(self) -> PublishSession<Arch, Tls> {
        let Self {
            resolve,
            ready_to_commit,
            lifecycle,
        } = self;
        let ResolveSession {
            dynamics,
            modules,
            guards,
            group_order,
            bindings,
            sources,
        } = resolve;
        assert!(
            dynamics.is_empty() && modules.is_empty(),
            "all pending modules must be relocated before publication"
        );
        PublishSession {
            guards,
            modules: ready_to_commit,
            order: group_order,
            bindings,
            pending_sources: sources,
            lifecycle,
        }
    }
}

impl<Arch, Tls> PublishSession<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn initializers(&self) -> Box<[ModuleHandle<Arch, Tls>]> {
        self.lifecycle
            .iter()
            .map(|id| {
                let module = self
                    .modules
                    .get(id)
                    .expect("lifecycle order must refer to a ready module");
                module.module.clone()
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub(crate) fn commit_into<Meta>(
        self,
        committed: &mut CommittedStorage<Meta, Arch, Tls>,
    ) -> Result<Box<[ModuleId]>>
    where
        Meta: Default,
    {
        let Self {
            guards,
            modules,
            order,
            bindings,
            pending_sources,
            lifecycle,
        } = self;
        let mut ready = modules;
        let mut committed_ids = Vec::with_capacity(ready.len());
        // Slot generations protect references resolved through the context;
        // no committed state is changed until every guard has been checked.
        for (slot, generation) in guards {
            if committed.generation(slot) != generation {
                return Err(LinkerError::context(LinkContextError::ModuleChanged {
                    id: ModuleId::from_slot(committed.context(), slot, generation),
                })
                .into());
            }
        }
        for &source in pending_sources.keys() {
            if committed.module_for_source(source).is_some() {
                return Err(
                    LinkerError::context(LinkContextError::SourceOccupied { source }).into(),
                );
            }
        }
        // Relocation records exact provider instances. Verify those providers
        // still exist, not merely another load of the same source.
        for (&slot, entry) in &ready {
            debug_assert_eq!(pending_sources.get(&entry.module.source_id()), Some(&slot));
            let providers_available = entry.module.state().with_bindings(|bindings| {
                bindings.iter().copied().all(|provider| {
                    pending_sources
                        .get(&provider.source_id())
                        .and_then(|slot| ready.get(slot))
                        .is_some_and(|entry| provider == entry.module.state().instance_id())
                        || committed.module_for_binding(provider).is_some()
                })
            });
            if !providers_available {
                let generation = committed.generation(slot);
                return Err(LinkerError::context(LinkContextError::ModuleChanged {
                    id: ModuleId::from_slot(committed.context(), slot, generation),
                })
                .into());
            }
        }
        for slot in order {
            let Some(entry) = ready.remove(&slot) else {
                continue;
            };
            let PendingModule {
                module,
                direct_deps,
                scope,
            } = entry;
            committed.insert(
                slot,
                StoredEntry::new(module, direct_deps, scope, 0, Meta::default()),
            );
            committed_ids.push(committed.make_module_id(slot));
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        for (key, modules) in bindings.iter() {
            for &module in modules {
                committed.bind_key(key, module);
            }
        }
        committed.extend_lifecycle(&lifecycle);
        Ok(committed_ids.into_boxed_slice())
    }
}
