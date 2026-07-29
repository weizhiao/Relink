use super::{
    context::LinkContext,
    storage::{CommittedStorage, KeySlot, ModuleId, ModuleSlot},
};
use crate::{
    Result,
    image::{LoadedCore, ModuleHandle, ModuleScope, ModuleScopeBuilder, RawDynamic},
    memory::RegionAccess,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

pub(crate) struct GraphEntry<P> {
    payload: P,
    direct_deps: Option<Box<[KeySlot]>>,
}

impl<P> GraphEntry<P> {
    #[inline]
    pub(crate) fn new(payload: P) -> Self {
        Self {
            payload,
            direct_deps: None,
        }
    }

    #[inline]
    pub(crate) fn with_direct_deps(payload: P, direct_deps: Box<[KeySlot]>) -> Self {
        Self {
            payload,
            direct_deps: Some(direct_deps),
        }
    }

    #[inline]
    pub(crate) fn payload(&self) -> &P {
        &self.payload
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> Option<&[KeySlot]> {
        self.direct_deps.as_deref()
    }

    #[inline]
    pub(crate) fn set_direct_deps(&mut self, direct_deps: Vec<KeySlot>) {
        self.direct_deps = Some(direct_deps.into_boxed_slice());
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (P, Option<Box<[KeySlot]>>) {
        (self.payload, self.direct_deps)
    }
}

pub(crate) struct ReadyCommit<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[KeySlot]>,
}

impl<Arch, Tls> Clone for ReadyCommit<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
        }
    }
}

impl<Arch, Tls> ReadyCommit<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn new(module: ModuleHandle<Arch, Tls>, direct_deps: Box<[KeySlot]>) -> Self {
        Self {
            module,
            direct_deps,
        }
    }
}

pub(crate) struct ModuleEntry<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[KeySlot]>,
}

impl<Arch, Tls> ModuleEntry<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(module: ModuleHandle<Arch, Tls>, direct_deps: Box<[KeySlot]>) -> Self {
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
    pub(crate) fn direct_deps(&self) -> &[KeySlot] {
        &self.direct_deps
    }
}

pub(crate) struct ResolveSession<P, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    pub(crate) dynamics: BTreeMap<KeySlot, GraphEntry<P>>,
    pub(crate) module_handles: BTreeMap<KeySlot, ModuleEntry<Arch, Tls>>,
    pub(crate) group_order: Vec<KeySlot>,
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
            module_handles: BTreeMap::new(),
            group_order: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn contains_pending(&self, slot: KeySlot) -> bool {
        self.dynamics.contains_key(&slot) || self.module_handles.contains_key(&slot)
    }

    #[inline]
    pub(crate) fn take_dynamics(&mut self) -> BTreeMap<KeySlot, GraphEntry<P>> {
        core::mem::take(&mut self.dynamics)
    }
}

pub(crate) struct LoadSession<
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    resolve: ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls>,
    ready_to_commit: BTreeMap<KeySlot, ReadyCommit<Arch, Tls>>,
    init_order: Vec<KeySlot>,
}

pub(crate) struct SessionCommit {
    pub(crate) ids: Box<[ModuleId]>,
    pub(crate) init_order: Box<[ModuleSlot]>,
}

impl<D: 'static, Arch, R, Tls> LoadSession<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            resolve: ResolveSession::new(),
            ready_to_commit: BTreeMap::new(),
            init_order: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn from_resolve<P>(resolve: ResolveSession<P, Arch, Tls>) -> Self {
        let ResolveSession {
            dynamics,
            module_handles,
            group_order,
        } = resolve;
        debug_assert!(dynamics.is_empty());
        Self {
            resolve: ResolveSession {
                dynamics: BTreeMap::new(),
                module_handles,
                group_order,
            },
            ready_to_commit: BTreeMap::new(),
            init_order: Vec::new(),
        }
    }
}

impl<D: 'static, Arch, R, Tls> LoadSession<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn resolve_mut(
        &mut self,
    ) -> &mut ResolveSession<RawDynamic<D, Arch, R, Tls>, Arch, Tls> {
        &mut self.resolve
    }

    #[inline]
    pub(crate) fn pending_is_empty(&self) -> bool {
        self.resolve.dynamics.is_empty() && self.resolve.module_handles.is_empty()
    }

    #[inline]
    pub(crate) fn take_pending_dynamic(
        &mut self,
        slot: KeySlot,
    ) -> Option<GraphEntry<RawDynamic<D, Arch, R, Tls>>> {
        self.resolve.dynamics.remove(&slot)
    }

    #[inline]
    pub(crate) fn push_ready<T>(&mut self, slot: KeySlot, module: T, direct_deps: Box<[KeySlot]>)
    where
        T: Into<ModuleHandle<Arch, Tls>>,
    {
        let previous = self
            .ready_to_commit
            .insert(slot, ReadyCommit::new(module.into(), direct_deps));
        debug_assert!(previous.is_none(), "ready commit entries must be unique");
    }

    #[inline]
    pub(crate) fn push_relocated(
        &mut self,
        slot: KeySlot,
        module: LoadedCore<D, Arch, R, Tls>,
        direct_deps: Box<[KeySlot]>,
    ) {
        self.init_order.push(slot);
        self.push_ready(slot, module, direct_deps);
    }

    pub(crate) fn mark_module_handles_ready(&mut self) {
        for (
            id,
            ModuleEntry {
                module,
                direct_deps,
            },
        ) in core::mem::take(&mut self.resolve.module_handles)
        {
            self.push_ready(id, module, direct_deps);
        }
    }

    pub(crate) fn loaded_root(&self, slot: KeySlot) -> Option<LoadedCore<D, Arch, R, Tls>> {
        self.ready_to_commit
            .get(&slot)?
            .module
            .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()
            .cloned()
    }

    pub(crate) fn init_order(&self) -> Vec<LoadedCore<D, Arch, R, Tls>> {
        self.init_order
            .iter()
            .map(|id| {
                self.ready_to_commit
                    .get(id)
                    .expect("initialization order must refer to a ready module")
                    .module
                    .downcast_ref::<LoadedCore<D, Arch, R, Tls>>()
                    .cloned()
                    .expect("initialization order must contain loaded dynamic modules")
            })
            .collect()
    }

    pub(crate) fn build_relocation_order(&self, root: KeySlot, order: &mut Vec<KeySlot>) {
        order.clear();
        let dynamic_len = self.resolve.dynamics.len();
        if order.capacity() < dynamic_len {
            order.reserve(dynamic_len - order.capacity());
        }

        let mut visited = BTreeSet::new();
        let pending_len = self.resolve.dynamics.len() + self.resolve.module_handles.len();
        let mut stack = Vec::with_capacity(pending_len.saturating_mul(2));
        stack.push((root, false));

        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                if self.resolve.dynamics.contains_key(&id) {
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
                        .module_handles
                        .get(&id)
                        .map(ModuleEntry::direct_deps)
                });
            let Some(direct_deps) = direct_deps else {
                continue;
            };

            stack.push((id, true));
            for dep in direct_deps.iter().rev().copied() {
                stack.push((dep, false));
            }
        }
    }

    pub(crate) fn build_scope<K, Meta>(
        &self,
        context: &LinkContext<K, D, Meta, Arch, Tls>,
    ) -> Result<ModuleScope<Arch, Tls>>
    where
        K: Ord,
    {
        let modules = self
            .resolve
            .group_order
            .iter()
            .map(|id| {
                if let Some(raw) = self.resolve.dynamics.get(id).map(GraphEntry::payload) {
                    let module = unsafe { LoadedCore::from_core(raw.core()) };
                    ModuleHandle::from(module)
                } else if let Some(module) =
                    self.resolve.module_handles.get(id).map(ModuleEntry::module)
                {
                    module.clone()
                } else {
                    context
                        .committed
                        .get_by_key(*id)
                        .cloned()
                        .expect("scope key must resolve to a committed module")
                }
            })
            .collect::<Vec<_>>();
        let mut scope = ModuleScopeBuilder::new(context.domain_id());
        scope.extend(modules);
        scope.into_scope()
    }

    pub(crate) fn commit_into<K, Meta>(
        self,
        committed: &mut CommittedStorage<K, D, Meta, Arch, Tls>,
    ) -> Result<SessionCommit>
    where
        K: Clone + Ord,
        Meta: Default,
    {
        let Self {
            resolve,
            ready_to_commit,
            init_order,
        } = self;
        let mut ready = ready_to_commit;
        let mut committed_ids = Vec::with_capacity(ready.len());
        for id in resolve.group_order.iter().copied() {
            if ready.contains_key(&id) {
                committed.ensure_module_slot(id);
            }
        }
        for id in resolve.group_order {
            let Some(entry) = ready.remove(&id) else {
                continue;
            };
            let ReadyCommit {
                module,
                direct_deps,
            } = entry;
            let direct_deps = committed.resolve_dep_edges(direct_deps)?;
            committed_ids.push(committed.insert(id, module, direct_deps, Meta::default(), 0));
        }
        assert!(
            ready.is_empty(),
            "ready commit entries must all be present in group_order"
        );
        Ok(SessionCommit {
            ids: committed_ids.into_boxed_slice(),
            init_order: init_order
                .into_iter()
                .map(|slot| {
                    committed
                        .module_for_key(slot)
                        .expect("initialized module must be committed")
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }
}
