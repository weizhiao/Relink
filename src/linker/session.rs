use super::{
    context::LinkContext,
    storage::{CommittedStorage, ModuleId, ModuleSlot},
};
use crate::{
    LinkContextError, LinkerError, Result,
    entity::EntitySet,
    image::{LoadedCore, ModuleHandle, ModuleScope, RawDynamic},
    memory::RegionAccess,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

pub(crate) struct GraphEntry<P> {
    payload: P,
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
    pending: Vec<(ModuleSlot, u32)>,
    observed: Vec<(ModuleSlot, u32)>,
    group_order: Vec<ModuleSlot>,
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
            pending: Vec::new(),
            observed: Vec::new(),
            group_order: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn contains_pending(&self, slot: ModuleSlot) -> bool {
        self.dynamics.contains_key(&slot) || self.modules.contains_key(&slot)
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

    pub(crate) fn set_direct_deps(&mut self, slot: ModuleSlot, direct_deps: Vec<ModuleSlot>) {
        self.dynamics
            .get_mut(&slot)
            .expect("session entry must exist for staged key")
            .set_direct_deps(direct_deps);
    }

    pub(crate) fn stage_dynamic(&mut self, slot: ModuleSlot, generation: u32, payload: P) {
        self.reserve(slot, generation);
        let previous = self.dynamics.insert(
            slot,
            GraphEntry {
                payload,
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
        self.reserve(slot, generation);
        let previous = self
            .modules
            .insert(slot, PendingModule::new(module, direct_deps));
        debug_assert!(previous.is_none(), "pending modules must be unique");
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
            pending,
            observed,
            group_order,
        } = self;
        (
            dynamics,
            ResolveSession {
                dynamics: BTreeMap::new(),
                modules,
                pending,
                observed,
                group_order,
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
    pub(crate) fn observe(&mut self, slot: ModuleSlot, generation: u32) {
        debug_assert!(!self.observed.iter().any(|(observed, _)| *observed == slot));
        self.observed.push((slot, generation));
    }

    #[inline]
    fn reserve(&mut self, slot: ModuleSlot, generation: u32) {
        debug_assert!(!self.pending.iter().any(|(pending, _)| *pending == slot));
        self.pending.push((slot, generation));
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn build_scope<K, Meta>(
        &self,
        context: &LinkContext<K, Meta, Arch, Tls>,
    ) -> Result<ModuleScope<Arch, Tls>>
    where
        K: Ord,
    {
        let modules = self
            .group_order
            .iter()
            .map(|id| {
                if let Some(raw) = self.dynamics.get(id).map(GraphEntry::payload) {
                    let module = unsafe { LoadedCore::from_core(raw.core()) };
                    ModuleHandle::from(module)
                } else if let Some(module) = self.modules.get(id).map(PendingModule::module) {
                    module.clone()
                } else {
                    context
                        .committed
                        .module(*id)
                        .map(|module| module.handle().clone())
                        .expect("scope slot must resolve to a committed module")
                }
            })
            .collect::<Vec<_>>();
        let mut scope = ModuleScope::new(context.domain_id());
        scope.extend(modules);
        Ok(scope)
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
    pub(crate) fn pending_is_empty(&self) -> bool {
        self.resolve.dynamics.is_empty() && self.resolve.modules.is_empty()
    }

    #[inline]
    pub(crate) fn take_pending_dynamic(
        &mut self,
        slot: ModuleSlot,
    ) -> Option<GraphEntry<RawDynamic<D, Arch, R, Tls>>> {
        self.resolve.dynamics.remove(&slot)
    }

    #[inline]
    pub(crate) fn push_ready<T>(
        &mut self,
        slot: ModuleSlot,
        module: T,
        direct_deps: Box<[ModuleSlot]>,
    ) where
        T: Into<ModuleHandle<Arch, Tls>>,
    {
        let previous = self
            .ready_to_commit
            .insert(slot, PendingModule::new(module.into(), direct_deps));
        debug_assert!(previous.is_none(), "ready commit entries must be unique");
    }

    #[inline]
    pub(crate) fn push_lifecycle(&mut self, slot: ModuleSlot) {
        self.lifecycle.push(slot);
    }

    pub(crate) fn mark_module_ready(&mut self, slot: ModuleSlot) {
        let PendingModule {
            module,
            direct_deps,
        } = self
            .resolve
            .modules
            .remove(&slot)
            .expect("missing pending module handle while preparing lifecycle");
        self.push_ready(slot, module, direct_deps);
    }

    pub(crate) fn root_module(&self, slot: ModuleSlot) -> Option<ModuleHandle<Arch, Tls>> {
        self.ready_to_commit
            .get(&slot)
            .map(|entry| entry.module.clone())
    }

    pub(crate) fn initializers(&self) -> Vec<ModuleHandle<Arch, Tls>> {
        self.lifecycle
            .iter()
            .map(|id| {
                self.ready_to_commit
                    .get(id)
                    .expect("lifecycle order must refer to a ready module")
                    .module
                    .clone()
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
    ) -> Result<Box<[ModuleId]>>
    where
        K: Clone + Ord,
        Meta: Default,
    {
        let Self {
            resolve,
            ready_to_commit,
            lifecycle,
        } = self;
        let mut ready = ready_to_commit;
        let mut committed_ids = Vec::with_capacity(ready.len());
        for &(slot, generation) in &resolve.pending {
            if committed.generation(slot) != generation || committed.contains_module(slot) {
                return Err(LinkerError::context(LinkContextError::ModuleChanged {
                    id: ModuleId::from_slot(committed.context(), slot, generation),
                })
                .into());
            }
        }
        for &(slot, generation) in &resolve.observed {
            if committed.generation(slot) != generation || !committed.contains_module(slot) {
                return Err(LinkerError::context(LinkContextError::ModuleChanged {
                    id: ModuleId::from_slot(committed.context(), slot, generation),
                })
                .into());
            }
        }
        for slot in resolve.group_order {
            let Some(entry) = ready.remove(&slot) else {
                continue;
            };
            let PendingModule {
                module,
                direct_deps,
            } = entry;
            committed.insert(slot, module, direct_deps, 0, Meta::default());
            committed_ids.push(committed.make_module_id(slot));
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        committed.extend_lifecycle(&lifecycle);
        Ok(committed_ids.into_boxed_slice())
    }
}
