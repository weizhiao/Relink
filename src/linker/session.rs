use super::storage::KeyId;
use crate::{
    image::ModuleHandle, memory::RegionAccess, relocation::RelocationArch, tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

pub(crate) struct GraphEntry<P> {
    payload: P,
    direct_deps: Option<Box<[KeyId]>>,
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
    pub(crate) fn with_direct_deps(payload: P, direct_deps: Box<[KeyId]>) -> Self {
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
    pub(crate) fn direct_deps(&self) -> Option<&[KeyId]> {
        self.direct_deps.as_deref()
    }

    #[inline]
    pub(crate) fn set_direct_deps(&mut self, direct_deps: Vec<KeyId>) {
        self.direct_deps = Some(direct_deps.into_boxed_slice());
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (P, Option<Box<[KeyId]>>) {
        (self.payload, self.direct_deps)
    }
}

pub(crate) struct ReadyCommit<D: 'static, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[KeyId]>,
    _marker: core::marker::PhantomData<fn() -> D>,
}

impl<D: 'static, Arch, Tls> Clone for ReadyCommit<D, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<D: 'static, Arch, Tls> ReadyCommit<D, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn new(module: ModuleHandle<Arch, Tls>, direct_deps: Box<[KeyId]>) -> Self {
        Self {
            module,
            direct_deps,
            _marker: core::marker::PhantomData,
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ModuleHandle<Arch, Tls>, Box<[KeyId]>) {
        (self.module, self.direct_deps)
    }
}

pub(crate) struct SyntheticEntry<Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[KeyId]>,
}

impl<Arch, Tls> SyntheticEntry<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(module: ModuleHandle<Arch, Tls>, direct_deps: Box<[KeyId]>) -> Self {
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
    pub(crate) fn direct_deps(&self) -> &[KeyId] {
        &self.direct_deps
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ModuleHandle<Arch, Tls>, Box<[KeyId]>) {
        (self.module, self.direct_deps)
    }
}

pub(crate) struct ResolveSession<P, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    pub(crate) dynamics: BTreeMap<KeyId, GraphEntry<P>>,
    pub(crate) synthetics: BTreeMap<KeyId, SyntheticEntry<Arch, Tls>>,
    pub(crate) group_order: Vec<KeyId>,
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
            synthetics: BTreeMap::new(),
            group_order: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn take_dynamics(&mut self) -> BTreeMap<KeyId, GraphEntry<P>> {
        core::mem::take(&mut self.dynamics)
    }
}

pub(crate) struct LoadSession<
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    resolve: ResolveSession<crate::image::RawDynamic<D, Arch, R, Tls>, Arch, Tls>,
    ready_to_commit: BTreeMap<KeyId, ReadyCommit<D, Arch, Tls>>,
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
        }
    }

    #[inline]
    pub(crate) fn from_resolve<P>(resolve: ResolveSession<P, Arch, Tls>) -> Self {
        let ResolveSession {
            dynamics,
            synthetics,
            group_order,
        } = resolve;
        debug_assert!(dynamics.is_empty());
        Self {
            resolve: ResolveSession {
                dynamics: BTreeMap::new(),
                synthetics,
                group_order,
            },
            ready_to_commit: BTreeMap::new(),
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
    ) -> &mut ResolveSession<crate::image::RawDynamic<D, Arch, R, Tls>, Arch, Tls> {
        &mut self.resolve
    }

    #[inline]
    pub(crate) fn pending_is_empty(&self) -> bool {
        self.resolve.dynamics.is_empty() && self.resolve.synthetics.is_empty()
    }

    #[inline]
    pub(crate) fn group_order(&self) -> &[KeyId] {
        &self.resolve.group_order
    }

    #[inline]
    pub(crate) fn pending_len(&self) -> usize {
        self.resolve.dynamics.len() + self.resolve.synthetics.len()
    }

    #[inline]
    pub(crate) fn pending_dynamic_len(&self) -> usize {
        self.resolve.dynamics.len()
    }

    #[inline]
    pub(crate) fn is_pending_dynamic(&self, id: KeyId) -> bool {
        self.resolve.dynamics.contains_key(&id)
    }

    #[inline]
    pub(crate) fn pending_direct_deps(&self, id: KeyId) -> Option<&[KeyId]> {
        if let Some(entry) = self.resolve.dynamics.get(&id) {
            return entry.direct_deps();
        }
        self.resolve
            .synthetics
            .get(&id)
            .map(SyntheticEntry::direct_deps)
    }

    #[inline]
    pub(crate) fn pending_dynamic(
        &self,
        id: KeyId,
    ) -> Option<&crate::image::RawDynamic<D, Arch, R, Tls>> {
        self.resolve.dynamics.get(&id).map(GraphEntry::payload)
    }

    #[inline]
    pub(crate) fn pending_synthetic(&self, id: KeyId) -> Option<&ModuleHandle<Arch, Tls>> {
        self.resolve.synthetics.get(&id).map(SyntheticEntry::module)
    }

    #[inline]
    pub(crate) fn insert_pending(
        &mut self,
        id: KeyId,
        raw: crate::image::RawDynamic<D, Arch, R, Tls>,
    ) {
        self.resolve.dynamics.insert(id, GraphEntry::new(raw));
    }

    #[inline]
    pub(crate) fn insert_resolved_pending(
        &mut self,
        id: KeyId,
        raw: crate::image::RawDynamic<D, Arch, R, Tls>,
        direct_deps: Box<[KeyId]>,
    ) {
        self.resolve
            .dynamics
            .insert(id, GraphEntry::with_direct_deps(raw, direct_deps));
    }

    #[inline]
    pub(crate) fn take_pending_dynamic(
        &mut self,
        id: KeyId,
    ) -> Option<GraphEntry<crate::image::RawDynamic<D, Arch, R, Tls>>> {
        self.resolve.dynamics.remove(&id)
    }

    #[inline]
    pub(crate) fn take_pending_synthetics(&mut self) -> BTreeMap<KeyId, SyntheticEntry<Arch, Tls>> {
        core::mem::take(&mut self.resolve.synthetics)
    }

    #[inline]
    pub(crate) fn push_ready<T>(&mut self, id: KeyId, module: T, direct_deps: Box<[KeyId]>)
    where
        T: Into<ModuleHandle<Arch, Tls>>,
    {
        let previous = self
            .ready_to_commit
            .insert(id, ReadyCommit::new(module.into(), direct_deps));
        debug_assert!(previous.is_none(), "ready commit entries must be unique");
    }

    #[inline]
    pub(crate) fn take_ready_to_commit(&mut self) -> BTreeMap<KeyId, ReadyCommit<D, Arch, Tls>> {
        core::mem::take(&mut self.ready_to_commit)
    }
}
