use super::{
    context::LinkContext,
    storage::{CommittedStorage, ModuleId, ModuleKey, ModuleSlot, ReservationReturns, StoredEntry},
};
use crate::{
    LinkContextError, LinkerError, Result,
    entity::EntitySet,
    image::{LoadedCore, ModuleHandle, ModuleInstanceId, ModuleScope, RawDynamic},
    input::ModuleSourceId,
    memory::RegionAccess,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    vec::Vec,
};

pub(crate) struct GraphEntry<P> {
    entry_key: ModuleKey,
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
    pub(crate) fn into_parts(self) -> (ModuleKey, P, Option<Box<[ModuleSlot]>>) {
        (self.entry_key, self.payload, self.direct_deps)
    }
}

struct PendingModule<Arch: RelocationArch> {
    entry_key: ModuleKey,
    module: ModuleHandle<Arch>,
    direct_deps: Box<[ModuleSlot]>,
}

impl<Arch> PendingModule<Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        entry_key: ModuleKey,
        module: ModuleHandle<Arch>,
        direct_deps: Box<[ModuleSlot]>,
    ) -> Self {
        Self {
            entry_key,
            module,
            direct_deps,
        }
    }

    #[inline]
    pub(crate) fn module(&self) -> &ModuleHandle<Arch> {
        &self.module
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> &[ModuleSlot] {
        &self.direct_deps
    }
}

struct ReadyModule<Arch: RelocationArch> {
    pending: PendingModule<Arch>,
    retained: ModuleScope<Arch>,
}

impl<Arch: RelocationArch> ReadyModule<Arch> {
    #[inline]
    fn new(pending: PendingModule<Arch>, retained: ModuleScope<Arch>) -> Self {
        Self { pending, retained }
    }

    #[inline]
    fn module(&self) -> &ModuleHandle<Arch> {
        self.pending.module()
    }
}

struct StagedSource {
    slot: ModuleSlot,
    generation: u32,
    ready_index: Option<usize>,
}

#[derive(Default)]
struct PendingSources {
    entries: BTreeMap<ModuleSourceId, StagedSource>,
    returns: Option<ReservationReturns>,
}

impl PendingSources {
    fn reserve<Meta, Arch: RelocationArch>(
        &mut self,
        committed: &mut CommittedStorage<Meta, Arch>,
        source: ModuleSourceId,
    ) -> (ModuleSlot, u32) {
        let Entry::Vacant(entry) = self.entries.entry(source) else {
            panic!("pending module sources must be unique");
        };
        self.returns
            .get_or_insert_with(|| committed.reserve_returns());
        let slot = committed.alloc_module();
        let generation = committed.generation(slot);
        entry.insert(StagedSource {
            slot,
            generation,
            ready_index: None,
        });
        (slot, generation)
    }

    fn disarm(&mut self) {
        self.returns = None;
    }
}

impl Drop for PendingSources {
    fn drop(&mut self) {
        if let Some(returns) = &self.returns {
            // Transactions may outlive their context or be dropped elsewhere.
            // Return only identities; the next allocation batch reclaims them.
            returns.lock().extend(
                self.entries
                    .values()
                    .map(|source| (source.slot, source.generation)),
            );
        }
    }
}

pub(crate) struct ResolveSession<P, Arch: RelocationArch> {
    dynamics: BTreeMap<ModuleSlot, GraphEntry<P>>,
    modules: BTreeMap<ModuleSlot, PendingModule<Arch>>,
    committed_deps: BTreeMap<ModuleSlot, Box<[ModuleSlot]>>,
    // Generations observed while resolving. Publication rejects the whole
    // transaction if any referenced slot changed before commit.
    guards: BTreeMap<ModuleSlot, u32>,
    group_order: Vec<ModuleSlot>,
    bindings: BTreeMap<ModuleKey, Vec<ModuleSlot>>,
    sources: PendingSources,
    pins: Vec<ModuleSlot>,
}

impl<P, Arch> ResolveSession<P, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            dynamics: BTreeMap::new(),
            modules: BTreeMap::new(),
            committed_deps: BTreeMap::new(),
            guards: BTreeMap::new(),
            group_order: Vec::new(),
            bindings: BTreeMap::new(),
            sources: PendingSources::default(),
            pins: Vec::new(),
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
    pub(crate) fn module_for_key(&self, key: &[u8]) -> Option<ModuleSlot> {
        self.bindings
            .get(key)
            .and_then(|modules| modules.first().copied())
    }

    #[inline]
    pub(crate) fn bind_key(&mut self, key: ModuleKey, module: ModuleSlot) {
        let modules = self.bindings.entry(key).or_default();
        if !modules.contains(&module) {
            modules.push(module);
        }
    }

    #[inline]
    pub(crate) fn module_for_source(&self, id: ModuleSourceId) -> Option<ModuleSlot> {
        self.sources.entries.get(&id).map(|source| source.slot)
    }

    #[inline]
    pub(crate) fn reserve_source<Meta>(
        &mut self,
        committed: &mut CommittedStorage<Meta, Arch>,
        source: ModuleSourceId,
    ) -> (ModuleSlot, u32) {
        self.sources.reserve(committed, source)
    }

    #[inline]
    pub(crate) fn pin(&mut self, slot: ModuleSlot) {
        if !self.pins.contains(&slot) {
            self.pins.push(slot);
        }
    }

    #[inline]
    pub(crate) fn direct_deps(&self, slot: ModuleSlot) -> Option<&[ModuleSlot]> {
        self.dynamics
            .get(&slot)
            .and_then(GraphEntry::direct_deps)
            .or_else(|| self.modules.get(&slot).map(PendingModule::direct_deps))
            .or_else(|| self.committed_deps.get(&slot).map(Box::as_ref))
    }

    #[inline]
    pub(crate) fn cache_committed_deps(
        &mut self,
        slot: ModuleSlot,
        direct_deps: Box<[ModuleSlot]>,
    ) {
        let previous = self.committed_deps.insert(slot, direct_deps);
        debug_assert!(
            previous.is_none(),
            "existing dependency edges must be unique"
        );
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

    pub(crate) fn set_module_deps(&mut self, slot: ModuleSlot, direct_deps: Box<[ModuleSlot]>) {
        self.modules
            .get_mut(&slot)
            .expect("session entry must exist for a staged module")
            .direct_deps = direct_deps;
    }

    pub(crate) fn stage_dynamic(
        &mut self,
        slot: ModuleSlot,
        generation: u32,
        entry_key: ModuleKey,
        payload: P,
        loader: Option<ModuleSlot>,
    ) {
        self.track(slot, generation);
        let previous = self.dynamics.insert(
            slot,
            GraphEntry {
                entry_key,
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
        entry_key: ModuleKey,
        module: ModuleHandle<Arch>,
        direct_deps: Box<[ModuleSlot]>,
    ) {
        self.track(slot, generation);
        let previous = self
            .modules
            .insert(slot, PendingModule::new(entry_key, module, direct_deps));
        debug_assert!(previous.is_none(), "pending modules must be unique");
    }

    pub(crate) fn split_dynamics<Q>(
        self,
    ) -> (BTreeMap<ModuleSlot, GraphEntry<P>>, ResolveSession<Q, Arch>) {
        let Self {
            dynamics,
            modules,
            committed_deps,
            guards,
            group_order,
            bindings,
            sources,
            pins,
        } = self;
        (
            dynamics,
            ResolveSession {
                dynamics: BTreeMap::new(),
                modules,
                committed_deps,
                guards,
                group_order,
                bindings,
                sources,
                pins,
            },
        )
    }

    pub(crate) fn restore_dynamic(
        &mut self,
        slot: ModuleSlot,
        entry_key: ModuleKey,
        payload: P,
        direct_deps: Box<[ModuleSlot]>,
    ) {
        let previous = self.dynamics.insert(
            slot,
            GraphEntry {
                entry_key,
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

impl<D: Send + Sync + 'static, Arch, R, Tls> ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn build_scope<Meta>(
        &self,
        context: &LinkContext<Meta, Arch, Tls>,
    ) -> ModuleScope<Arch> {
        let mut scope = Vec::with_capacity(self.group_order.len());
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
        ModuleScope::from_admitted(context.domain_id(), scope)
    }
}

pub(crate) struct LoadSession<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    resolve: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch>,
    // Relocation appends modules in lifecycle order, which is also the order
    // used for initialization and publication.
    ready_to_commit: Vec<(ModuleSlot, ReadyModule<Arch>)>,
}

pub(crate) struct PublishSession<Arch: RelocationArch> {
    guards: BTreeMap<ModuleSlot, u32>,
    modules: Vec<(ModuleSlot, ReadyModule<Arch>)>,
    bindings: BTreeMap<ModuleKey, Vec<ModuleSlot>>,
    pending_sources: PendingSources,
    pins: Vec<ModuleSlot>,
}

pub(crate) struct CommitResult {
    pub(crate) modules: Box<[ModuleId]>,
    pub(crate) pins: Box<[ModuleSlot]>,
}

impl<D: Send + Sync + 'static, Arch, R, Tls> LoadSession<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn from_resolve(resolve: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch>) -> Self {
        let pending_len = resolve.dynamics.len() + resolve.modules.len();
        Self {
            resolve,
            ready_to_commit: Vec::with_capacity(pending_len),
        }
    }

    #[inline]
    pub(crate) fn take_pending_dynamic(
        &mut self,
        slot: ModuleSlot,
    ) -> Option<GraphEntry<RawDynamic<D, Arch, R, Tls>>> {
        self.resolve.dynamics.remove(&slot)
    }

    pub(crate) fn build_retained_scopes(
        &self,
        root: ModuleSlot,
        local: &ModuleScope<Arch>,
        modules: &[ModuleSlot],
    ) -> Vec<ModuleScope<Arch>> {
        let group_order = self.resolve.group_order();
        assert_eq!(
            group_order.len(),
            local.len(),
            "resolved group order and module scope must stay aligned"
        );
        let mut indices = None;

        modules
            .iter()
            .map(|&module| {
                if module == root {
                    return local.clone();
                }

                let indices = indices.get_or_insert_with(|| {
                    group_order
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(index, slot)| (slot, index))
                        .collect::<BTreeMap<_, _>>()
                });

                let mut scope = Vec::new();
                let mut visited = EntitySet::default();
                let mut pending = VecDeque::from([module]);
                while let Some(slot) = pending.pop_front() {
                    if !visited.insert(slot) {
                        continue;
                    }
                    let index = indices
                        .get(&slot)
                        .copied()
                        .expect("module dependency must belong to the resolved load group");
                    scope.push(local[index].clone());
                    let direct_deps = self
                        .resolve
                        .direct_deps(slot)
                        .expect("resolved module must retain its direct dependencies");
                    pending.extend(direct_deps.iter().copied());
                }
                ModuleScope::from_admitted(local.domain_id(), scope)
            })
            .collect()
    }

    #[inline]
    pub(crate) fn push_ready(
        &mut self,
        slot: ModuleSlot,
        entry_key: ModuleKey,
        loaded: LoadedCore<D, Arch, R, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        retained: ModuleScope<Arch>,
    ) {
        let module = loaded.into_module_handle();
        let pending = PendingModule {
            entry_key,
            module,
            direct_deps,
        };
        self.stage_ready(slot, pending, retained);
    }

    #[inline]
    fn stage_ready(
        &mut self,
        slot: ModuleSlot,
        pending: PendingModule<Arch>,
        retained: ModuleScope<Arch>,
    ) {
        let source = self
            .resolve
            .sources
            .entries
            .get_mut(&pending.module.source_id())
            .expect("ready module source must be staged");
        debug_assert_eq!(source.slot, slot);
        debug_assert!(
            source.ready_index.is_none(),
            "ready commit entries must be unique"
        );
        source.ready_index = Some(self.ready_to_commit.len());
        self.ready_to_commit
            .push((slot, ReadyModule::new(pending, retained)));
    }

    pub(crate) fn mark_module_ready(&mut self, slot: ModuleSlot, retained: ModuleScope<Arch>) {
        let module = self
            .resolve
            .modules
            .remove(&slot)
            .expect("missing pending module handle while preparing lifecycle");
        self.stage_ready(slot, module, retained);
    }

    pub(crate) fn build_lifecycle_order(&self, root: ModuleSlot, order: &mut Vec<ModuleSlot>) {
        order.clear();
        let pending_len = self.resolve.dynamics.len() + self.resolve.modules.len();
        order.reserve(pending_len);

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

    pub(crate) fn into_publish(self) -> PublishSession<Arch> {
        let Self {
            resolve,
            ready_to_commit,
        } = self;
        let ResolveSession {
            dynamics,
            modules,
            committed_deps: _,
            guards,
            group_order: _,
            bindings,
            sources,
            pins,
        } = resolve;
        assert!(
            dynamics.is_empty() && modules.is_empty(),
            "all pending modules must be relocated before publication"
        );
        PublishSession {
            guards,
            modules: ready_to_commit,
            bindings,
            pending_sources: sources,
            pins,
        }
    }
}

impl<Arch> PublishSession<Arch>
where
    Arch: RelocationArch,
{
    pub(crate) fn initializers(&self) -> Box<[ModuleHandle<Arch>]> {
        self.modules
            .iter()
            .map(|(_, entry)| entry.module().clone())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub(crate) fn commit_into<Meta>(
        self,
        committed: &mut CommittedStorage<Meta, Arch>,
    ) -> Result<CommitResult>
    where
        Meta: Default,
    {
        let Self {
            guards,
            modules,
            bindings,
            mut pending_sources,
            mut pins,
        } = self;
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
        for &source in pending_sources.entries.keys() {
            if committed.module_for_source(source).is_some() {
                return Err(
                    LinkerError::context(LinkContextError::SourceOccupied { source }).into(),
                );
            }
        }
        // Relocation records exact provider instances. Verify those providers
        // still exist, not merely another load of the same source.
        for (slot, entry) in &modules {
            let module = entry.module();
            debug_assert_eq!(
                pending_sources
                    .entries
                    .get(&module.source_id())
                    .map(|source| source.slot),
                Some(*slot)
            );
            let find_provider = |provider: ModuleInstanceId| {
                pending_sources
                    .entries
                    .get(&provider.source_id())
                    .and_then(|source| source.ready_index)
                    .and_then(|index| modules.get(index))
                    .filter(|(_, entry)| provider == entry.module().state().instance_id())
                    .map(|(slot, _)| *slot)
                    .or_else(|| committed.module_for_binding(provider))
            };
            let missing_provider = module.state().with_effects(|bindings, requested_pins| {
                for provider in bindings.iter().copied() {
                    if find_provider(provider).is_none() {
                        return Some(provider);
                    }
                }
                for provider in requested_pins.iter().copied() {
                    let Some(slot) = find_provider(provider) else {
                        return Some(provider);
                    };
                    if !pins.contains(&slot) {
                        pins.push(slot);
                    }
                }
                None
            });
            if let Some(id) = missing_provider {
                return Err(
                    LinkerError::context(LinkContextError::DependencyMissing { id }).into(),
                );
            }
        }
        let committed_ids = committed.publish(modules.len(), |publication| {
            let mut committed_ids = Vec::with_capacity(modules.len());
            for (slot, entry) in modules {
                let ReadyModule { pending, retained } = entry;
                let PendingModule {
                    entry_key,
                    module,
                    direct_deps,
                } = pending;
                committed_ids.push(publication.insert(
                    slot,
                    StoredEntry::new(entry_key, module, direct_deps, retained, 0, Meta::default()),
                ));
            }
            for (key, modules) in bindings {
                for module in modules {
                    publication.bind_key(key.clone(), module);
                }
            }
            for &slot in &pins {
                publication.pin(slot);
            }
            committed_ids
        });
        pending_sources.disarm();
        Ok(CommitResult {
            modules: committed_ids.into_boxed_slice(),
            pins: pins.into_boxed_slice(),
        })
    }
}
