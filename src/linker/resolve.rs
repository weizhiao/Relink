use super::{
    resolver::{
        DependencyOwner, DependencyRequest, KeyResolver, ResolvedKey, RootRequest, SearchOwner,
    },
    session::ResolveSession,
    storage::{CommittedStorage, ModuleSlot},
};
use crate::{
    LinkResolverError, LinkerError, LoaderRun, ParsePhdrError, Result,
    arch::NativeArch,
    entity::EntitySet,
    image::{ModuleHandle, RawDynamic, ScannedDynamic, ScannedElf},
    memory::{HostRegion, RegionAccess},
    observer::{LinkerObserver, LoadObserver},
    os::Mmap,
    relocation::RelocationArch,
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::borrow::Borrow;

#[inline]
fn push_dep(deps: &mut Vec<ModuleSlot>, dep: ModuleSlot) {
    if !deps.contains(&dep) {
        deps.push(dep);
    }
}

pub(crate) struct ResolveContext<
    'a,
    K: Clone,
    Arch: RelocationArch = NativeArch,
    P = (),
    Tls: TlsResolver<Arch> = (),
> {
    committed: &'a mut CommittedStorage<K, Arch, Tls>,
    session: &'a mut ResolveSession<P, Arch, Tls>,
}

pub(crate) type LoadResolveContext<'a, K, D, Arch = NativeArch, R = HostRegion, Tls = ()> =
    ResolveContext<'a, K, Arch, RawDynamic<D, Arch, R, Tls>, Tls>;

pub(crate) type ScanResolveContext<'a, K, Arch = NativeArch, Tls = ()> =
    ResolveContext<'a, K, Arch, ScannedDynamic<Arch>, Tls>;

impl<'a, K: Clone, Arch, P, Tls> ResolveContext<'a, K, Arch, P, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<K, Arch, Tls>,
        session: &'a mut ResolveSession<P, Arch, Tls>,
    ) -> Self {
        Self { committed, session }
    }
}

impl<K, Arch, P, Tls> ResolveContext<'_, K, Arch, P, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    P: DependencyOwner,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn contains_pending(&self, slot: ModuleSlot) -> bool {
        self.session.contains_pending(slot)
    }

    #[inline]
    fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.known_module(key).is_some()
    }

    fn ensure_new<Q>(&self, key: &Q) -> Result<()>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if self.contains_key(key) {
            return Err(LinkerError::resolver(LinkResolverError::NewKeyAlreadyKnown).into());
        }
        Ok(())
    }

    fn known_module<Q>(&self, key: &Q) -> Option<ModuleSlot>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let key = self.committed.key_slot_for(key)?;
        let module = self.committed.module_for_key(key)?;
        (self.session.contains_pending(module) || self.committed.contains_module(module))
            .then_some(module)
    }

    fn stage_dynamic(&mut self, key: K, payload: P) -> ModuleSlot {
        let key = self.committed.intern_key(key);
        let slot = self.committed.intern_module(key);
        let generation = self.committed.generation(slot);
        self.session.stage_dynamic(slot, generation, payload);
        slot
    }

    fn stage_module(
        &mut self,
        key: K,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
    ) -> Result<ModuleSlot> {
        self.committed.ensure_domain(module.domain_id())?;
        let key = self.committed.intern_key(key);
        let slot = self.committed.intern_module(key);
        let generation = self.committed.generation(slot);
        self.session
            .stage_module(slot, generation, module, direct_deps);
        Ok(slot)
    }

    fn existing<Q>(&mut self, key: &Q) -> Result<ModuleSlot>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.known_module(key)
            .ok_or_else(|| LinkerError::resolver(LinkResolverError::ExistingKeyMissing).into())
    }

    fn stage_module_deps<'cfg, D, Obs, F, M, Exec>(
        &mut self,
        deps: Vec<ResolvedKey<'cfg, K, Arch, Tls>>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        mut stage: F,
    ) -> Result<Box<[ModuleSlot]>>
    where
        D: Send + Sync + 'static,
        Obs: LoadObserver<D, Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        let mut direct_deps = Vec::with_capacity(deps.len());
        for dep in deps {
            push_dep(&mut direct_deps, stage(self, dep, loader)?);
        }
        Ok(direct_deps.into_boxed_slice())
    }

    fn known_direct_deps(&self, slot: ModuleSlot) -> Option<&[ModuleSlot]> {
        if let Some(direct_deps) = self.session.direct_deps(slot) {
            return Some(direct_deps);
        }

        self.committed
            .module(slot)
            .map(|module| module.direct_deps())
    }

    fn owner(&self, slot: ModuleSlot) -> &dyn DependencyOwner {
        self.session
            .dynamic_payload(slot)
            .expect("dependency owner must be present for a staged dynamic module")
            as &dyn DependencyOwner
    }

    pub(crate) fn resolve_root<'cfg, Q>(
        &self,
        key: &K,
        owner: Option<SearchOwner<'_>>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
    {
        let contains_key = |key: &Q| self.contains_key(key);
        let req = RootRequest::new(key, owner, &contains_key);
        resolver.load_root(&req)
    }

    fn direct_deps_for<'cfg, D, Obs, F, M, Exec, Q>(
        &mut self,
        slot: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
        stage: &mut F,
    ) -> Result<&[ModuleSlot]>
    where
        D: Send + Sync + 'static,
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        if !self.session.contains_pending(slot) && self.committed.contains_module(slot) {
            self.session.observe(slot, self.committed.generation(slot));
        }
        if self.known_direct_deps(slot).is_none() {
            let needed_len = self.owner(slot).needed_len();
            let mut direct_deps = Vec::with_capacity(needed_len);
            for idx in 0..needed_len {
                let key = {
                    let contains_key = |key: &Q| self.contains_key(key);
                    let owner = self.owner(slot);
                    let owner_key = self.committed.key(self.committed.entry_key(slot));
                    let req = DependencyRequest::new(owner_key, owner, idx, &contains_key);
                    resolver.resolve_dependency(&req)?
                };
                push_dep(&mut direct_deps, stage(self, key, loader)?);
            }
            self.session.set_direct_deps(slot, direct_deps);
        }
        Ok(self
            .known_direct_deps(slot)
            .expect("resolved module must retain its direct dependencies"))
    }

    fn resolve_dependency_graph_with<'cfg, D, Obs, F, M, Exec, Q>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
        mut stage: F,
    ) -> Result<()>
    where
        D: Send + Sync + 'static,
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        let mut visited = EntitySet::default();
        visited.insert(root);
        let mut group_order = Vec::new();
        group_order.push(root);
        let mut cursor = 0;
        while cursor < group_order.len() {
            let slot = group_order[cursor];
            cursor += 1;
            for &dep in self.direct_deps_for(slot, loader, resolver, &mut stage)? {
                if visited.insert(dep) {
                    group_order.push(dep);
                }
            }
        }
        self.session.set_group_order(group_order);
        Ok(())
    }
}

impl<K, D: Send + Sync + 'static, Arch, R, Tls>
    ResolveContext<'_, K, Arch, RawDynamic<D, Arch, R, Tls>, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage<'cfg, Obs, M, Exec, Q>(
        &mut self,
        resolved: ResolvedKey<'cfg, K, Arch, Tls>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<ModuleSlot>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        match resolved {
            ResolvedKey::Existing(key) => self.existing(key.borrow()),
            ResolvedKey::Load { key, reader } => {
                self.ensure_new(key.borrow())?;
                let raw = loader.load_dynamic(reader)?;
                Ok(self.stage_dynamic(key, raw))
            }
            ResolvedKey::Module { key, module, deps } => {
                self.ensure_new(key.borrow())?;
                let direct_deps = self.stage_module_deps(deps, loader, |ctx, dep, loader| {
                    ctx.stage::<Obs, M, Exec, Q>(dep, loader)
                })?;
                self.stage_module(key, module, direct_deps)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<'cfg, Obs, M, Exec, Q>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
    ) -> Result<()>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage(resolved, loader)
        })
    }
}

impl<K, Arch, Tls> ResolveContext<'_, K, Arch, ScannedDynamic<Arch>, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage<D, Obs, M, Exec, Q>(
        &mut self,
        resolved: ResolvedKey<'static, K, Arch, Tls>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<ModuleSlot>
    where
        D: Send + Sync + 'static,
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        match resolved {
            ResolvedKey::Existing(key) => self.existing(key.borrow()),
            ResolvedKey::Load { key, reader } => {
                self.ensure_new(key.borrow())?;
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(ParsePhdrError::MissingDynamicSection.into());
                };
                Ok(self.stage_dynamic(key, module))
            }
            ResolvedKey::Module { key, module, deps } => {
                self.ensure_new(key.borrow())?;
                let direct_deps = self.stage_module_deps(deps, loader, |ctx, dep, loader| {
                    ctx.stage::<D, Obs, M, Exec, Q>(dep, loader)
                })?;
                self.stage_module(key, module, direct_deps)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<D, Obs, M, Exec, Q>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
    ) -> Result<()>
    where
        D: Send + Sync + 'static,
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage(resolved, loader)
        })
    }
}
