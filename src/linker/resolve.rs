use super::{
    request::{DependencyOwner, DependencyRequest, LoadObserver, StagedDynamic, VisibleModules},
    resolver::{KeyResolver, ResolvedKey},
    session::{ResolveSession, extend_breadth_first},
    storage::{CommittedStorage, KeyId},
};
use crate::{
    LinkerError, Loader, Result,
    image::{RawDynamic, ScannedDynamic, ScannedElf},
    loader::LoadHook,
    os::Mmap,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::vec::Vec;

pub(crate) struct ResolveContext<
    'a,
    K: Clone,
    D: 'static,
    Meta = (),
    V = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    P = (),
> {
    committed: &'a mut CommittedStorage<K, D, Meta, Arch>,
    visible_modules: &'a V,
    session: &'a mut ResolveSession<P>,
}

pub(crate) type LoadResolveContext<'a, K, D, Meta = (), V = (), Arch = crate::arch::NativeArch> =
    ResolveContext<'a, K, D, Meta, V, Arch, RawDynamic<D, Arch>>;

pub(crate) type ScanResolveContext<'a, K, D, Meta = (), V = (), Arch = crate::arch::NativeArch> =
    ResolveContext<'a, K, D, Meta, V, Arch, ScannedDynamic<Arch>>;

impl<'a, K: Clone, D: 'static, Meta, V, Arch, P> ResolveContext<'a, K, D, Meta, V, Arch, P>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<K, D, Meta, Arch>,
        visible_modules: &'a V,
        session: &'a mut ResolveSession<P>,
    ) -> Self {
        Self {
            committed,
            visible_modules,
            session,
        }
    }
}

impl<K, D: 'static, Meta, V, Arch, P> ResolveContext<'_, K, D, Meta, V, Arch, P>
where
    K: Clone + Ord,
    V: VisibleModules<K, D, Arch>,
    Arch: RelocationArch,
    P: DependencyOwner,
{
    #[inline]
    pub(crate) fn contains_pending(&self, id: KeyId) -> bool {
        self.session.contains(id)
    }

    #[inline]
    fn contains_visible_or_pending(&self, key: &K) -> bool {
        self.committed
            .key_id(key)
            .is_some_and(|id| self.session.contains(id) || self.committed.contains(id))
            || self.visible_modules.contains_key(key)
    }

    fn intern_key(&mut self, key: K) -> KeyId {
        self.committed.intern_key(key)
    }

    fn key(&self, id: KeyId) -> Option<&K> {
        self.committed.key(id)
    }

    fn known_direct_deps(&mut self, id: KeyId) -> Option<Vec<KeyId>> {
        if let Some(entry) = self.session.entries.get(&id) {
            return entry.direct_deps().map(<[KeyId]>::to_vec);
        }

        if let Some(direct_deps) = self.committed.direct_deps(id) {
            return Some(direct_deps.to_vec());
        }

        let key = self.committed.key(id)?.clone();
        self.visible_modules.direct_deps(&key).map(|deps| {
            deps.into_vec()
                .into_iter()
                .map(|key| self.intern_key(key))
                .collect()
        })
    }

    fn owner(&self, id: KeyId) -> Option<&dyn DependencyOwner> {
        self.session
            .entries
            .get(&id)
            .map(|entry| &entry.payload as &dyn DependencyOwner)
    }

    fn set_direct_deps(&mut self, id: KeyId, direct_deps: Vec<KeyId>) {
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .expect("session entry must exist for staged key");
        entry.set_direct_deps(direct_deps);
    }

    fn resolve_dependency_edge<'cfg>(
        &self,
        id: KeyId,
        needed_index: usize,
        resolver: &mut impl KeyResolver<'cfg, K>,
    ) -> Result<ResolvedKey<'cfg, K>>
    where
        K: 'cfg,
    {
        let is_visible = |key: &K| self.contains_visible_or_pending(key);
        let req: DependencyRequest<'_, K> = {
            let owner = self
                .owner(id)
                .expect("missing dependency owner while building request");
            let owner_key = self
                .key(id)
                .expect("dependency owner id must resolve to an interned key");
            DependencyRequest::new(owner_key, owner, needed_index, &is_visible)
        };

        resolver.resolve_dependency(&req)
    }

    fn direct_deps_for_with<'cfg, M, H, Tls, F>(
        &mut self,
        id: KeyId,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'cfg, K>,
        stage: &mut F,
    ) -> Result<Vec<KeyId>>
    where
        K: 'cfg,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
        F: FnMut(&mut Self, ResolvedKey<'cfg, K>, &mut Loader<M, H, D, Tls, Arch>) -> Result<KeyId>,
    {
        if let Some(direct_deps) = self.known_direct_deps(id) {
            return Ok(direct_deps);
        }

        let needed_len = self
            .owner(id)
            .expect("missing dependency owner while resolving direct deps")
            .needed_len();
        let mut direct_deps = Vec::with_capacity(needed_len);
        for idx in 0..needed_len {
            let resolved_key = self.resolve_dependency_edge(id, idx, resolver)?;
            let dep_id = stage(self, resolved_key, loader)?;
            if !direct_deps.contains(&dep_id) {
                direct_deps.push(dep_id);
            }
        }
        self.set_direct_deps(id, direct_deps.clone());
        Ok(direct_deps)
    }

    fn resolve_dependency_graph_with<'cfg, M, H, Tls, F>(
        &mut self,
        root: KeyId,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'cfg, K>,
        mut stage: F,
    ) -> Result<()>
    where
        K: 'cfg,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
        F: FnMut(&mut Self, ResolvedKey<'cfg, K>, &mut Loader<M, H, D, Tls, Arch>) -> Result<KeyId>,
    {
        let mut group_order = Vec::new();
        extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for_with(*key, loader, resolver, &mut stage)
        })?;
        self.session.group_order = group_order;
        Ok(())
    }
}

impl<K, D: 'static, Meta, V, Arch> ResolveContext<'_, K, D, Meta, V, Arch, RawDynamic<D, Arch>>
where
    K: Clone + Ord,
    V: VisibleModules<K, D, Arch>,
    Arch: RelocationArch,
{
    pub(crate) fn stage_resolved<'cfg, M, H, Tls, O>(
        &mut self,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        observer: &mut O,
    ) -> Result<KeyId>
    where
        K: 'cfg,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
        O: LoadObserver<K, D, Arch>,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                if self.contains_visible_or_pending(&key) {
                    return Ok(self.intern_key(key));
                }
                Err(LinkerError::resolver(
                    "resolved existing module is not visible in the current link context",
                )
                .into())
            }
            ResolvedKey::Load { key, reader } => {
                assert!(
                    !self.contains_visible_or_pending(&key),
                    "resolved reader produced an already-known key; use ResolvedKey::Existing to reuse a visible module"
                );
                let raw = loader.load_dynamic(reader)?;
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                let id = self.intern_key(key);
                self.session.insert_entry(id, raw);
                Ok(id)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<'cfg, M, H, Tls, O>(
        &mut self,
        root: KeyId,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'cfg, K>,
        observer: &mut O,
    ) -> Result<()>
    where
        K: 'cfg,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
        O: LoadObserver<K, D, Arch>,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage_resolved(resolved, loader, observer)
        })
    }
}

impl<K, D: 'static, Meta, V, Arch> ResolveContext<'_, K, D, Meta, V, Arch, ScannedDynamic<Arch>>
where
    K: Clone + Ord,
    V: VisibleModules<K, D, Arch>,
    Arch: RelocationArch,
{
    pub(crate) fn stage_resolved<M, H, Tls>(
        &mut self,
        resolved: ResolvedKey<'static, K>,
        loader: &mut Loader<M, H, D, Tls, Arch>,
    ) -> Result<KeyId>
    where
        K: 'static,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                if self.contains_visible_or_pending(&key) {
                    return Ok(self.intern_key(key));
                }
                Err(LinkerError::resolver("scan resolver referenced an unknown visible key").into())
            }
            ResolvedKey::Load { key, reader } => {
                if self.contains_visible_or_pending(&key) {
                    return Err(LinkerError::resolver(
                        "scan resolver attached metadata to an already-known key; use Existing to reuse it",
                    )
                    .into());
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(crate::ParsePhdrError::MissingDynamicSection.into());
                };
                let id = self.intern_key(key);
                self.session.insert_entry(id, module);
                Ok(id)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<M, H, Tls>(
        &mut self,
        root: KeyId,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'static, K>,
    ) -> Result<()>
    where
        K: 'static,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage_resolved(resolved, loader)
        })
    }
}
