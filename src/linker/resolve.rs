use super::{
    resolver::{
        DependencyRequest, DependencySource, KeyResolver, LoaderVisitor, ResolvedKey, RootRequest,
    },
    session::ResolveSession,
    storage::{CommittedStorage, ModuleSlot},
};
use crate::{
    LinkResolverError, LinkerError, LoaderRun, ParsePhdrError, Result,
    arch::NativeArch,
    entity::EntitySet,
    image::{ModuleHandle, ModuleSearch, PathTokens, RawDynamic, ScannedDynamic, ScannedElf},
    input::FileId,
    memory::{HostRegion, RegionAccess},
    observer::{LinkerObserver, LoadObserver},
    os::Mmap,
    relocation::RelocationArch,
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

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
    Meta = (),
> {
    committed: &'a mut CommittedStorage<K, Meta, Arch, Tls>,
    session: &'a mut ResolveSession<P, Arch, Tls>,
    tokens: PathTokens,
}

pub(crate) type LoadResolveContext<
    'a,
    K,
    D,
    Arch = NativeArch,
    R = HostRegion,
    Tls = (),
    Meta = (),
> = ResolveContext<'a, K, Arch, RawDynamic<D, Arch, R, Tls>, Tls, Meta>;

pub(crate) type ScanResolveContext<'a, K, Arch = NativeArch, Tls = (), Meta = ()> =
    ResolveContext<'a, K, Arch, ScannedDynamic<Arch>, Tls, Meta>;

impl<'a, K: Clone, Arch, P, Tls, Meta> ResolveContext<'a, K, Arch, P, Tls, Meta>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<K, Meta, Arch, Tls>,
        session: &'a mut ResolveSession<P, Arch, Tls>,
        tokens: PathTokens,
    ) -> Self {
        Self {
            committed,
            session,
            tokens,
        }
    }
}

impl<K, Arch, P, Tls, Meta> ResolveContext<'_, K, Arch, P, Tls, Meta>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    P: DependencySource,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn contains_pending(&self, slot: ModuleSlot) -> bool {
        self.session.contains_pending(slot)
    }

    #[inline]
    fn contains_key(&self, key: &K) -> bool {
        self.known_module(key).is_some()
    }

    fn ensure_new(&self, key: &K) -> Result<()> {
        if self.contains_key(key) {
            return Err(LinkerError::resolver(LinkResolverError::NewKeyAlreadyKnown).into());
        }
        Ok(())
    }

    fn known_module(&self, key: &K) -> Option<ModuleSlot> {
        let key = self.committed.key_slot_for(key)?;
        self.committed
            .canonical_module(key)
            .filter(|module| {
                self.session.contains_pending(*module) || self.committed.contains_module(*module)
            })
            .or_else(|| self.committed.alias_module(key))
            .or_else(|| self.session.alias_module(key))
    }

    fn reuse_file(&mut self, key: &K, id: Option<FileId>) -> Option<ModuleSlot> {
        let id = id?;
        let slot = self
            .committed
            .file_module(id)
            .or_else(|| self.session.file_module(id))?;
        self.stage_alias(Some(key.clone()), slot);
        Some(slot)
    }

    fn reuse_module(&mut self, key: &K, module: &ModuleHandle<Arch, Tls>) -> Option<ModuleSlot> {
        let slot = self
            .committed
            .matching_module(module)
            .or_else(|| self.session.matching_module(module))?;
        self.stage_alias(Some(key.clone()), slot);
        Some(slot)
    }

    fn stage_alias(&mut self, alias: Option<K>, slot: ModuleSlot) {
        if let Some(alias) = alias {
            let alias = self.committed.intern_key(alias);
            self.session.stage_alias(alias, slot);
        }
    }

    fn stage_dynamic<Resolver>(
        &mut self,
        key: K,
        payload: P,
        loader: Option<ModuleSlot>,
        resolver: &Resolver,
    ) -> ModuleSlot
    where
        Resolver: KeyResolver<K, Arch, Tls>,
    {
        let search = payload.search();
        let file = search.file_id();
        let alias = search.soname().and_then(|name| resolver.map_name(name));
        let key = self.committed.intern_key(key);
        let slot = self.committed.intern_module(key);
        let generation = self.committed.generation(slot);
        self.session
            .stage_dynamic(slot, generation, payload, loader);
        self.session.stage_file(file, slot);
        self.stage_alias(alias, slot);
        slot
    }

    fn stage_module<Resolver>(
        &mut self,
        key: K,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        resolver: &Resolver,
    ) -> ModuleSlot
    where
        Resolver: KeyResolver<K, Arch, Tls>,
    {
        let search = module.search();
        let file = search.and_then(ModuleSearch::file_id);
        let alias = search
            .and_then(ModuleSearch::soname)
            .and_then(|name| resolver.map_name(name));
        let key = self.committed.intern_key(key);
        let slot = self.committed.intern_module(key);
        let generation = self.committed.generation(slot);
        self.session
            .stage_module(slot, generation, module, direct_deps);
        self.session.stage_file(file, slot);
        self.stage_alias(alias, slot);
        slot
    }

    fn existing(&self, key: &K) -> Result<ModuleSlot> {
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

    fn source(&self, slot: ModuleSlot) -> &P {
        self.session
            .dynamic_payload(slot)
            .expect("dependency source must be present for a staged dynamic module")
    }

    fn search(&self, slot: ModuleSlot) -> Option<&ModuleSearch> {
        self.session
            .dynamic_payload(slot)
            .map(DependencySource::search)
            .or_else(|| {
                self.committed
                    .module(slot)
                    .and_then(|module| module.handle().search())
            })
    }

    fn visit_loaders(&self, mut slot: ModuleSlot, visitor: &mut LoaderVisitor<'_>) -> Result<()> {
        loop {
            if let Some(search) = self.search(slot)
                && !visitor(search)?
            {
                return Ok(());
            }
            let Some(loader) = self.session.loader(slot) else {
                return Ok(());
            };
            slot = loader;
        }
    }

    pub(crate) fn resolve_root<'cfg, Resolver>(
        &self,
        request: &Resolver::Request,
        key: Option<K>,
        caller: Option<ModuleSlot>,
        resolver: &Resolver,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg,
        Resolver: KeyResolver<K, Arch, Tls>,
    {
        let contains_key = |key: &K| self.contains_key(key);
        let req = RootRequest::new(
            request,
            key,
            caller.and_then(|slot| self.search(slot)),
            &self.tokens,
            &contains_key,
        );
        resolver.resolve_root(&req)
    }

    fn direct_deps_for<'cfg, D, Obs, F, M, Exec, Resolver>(
        &mut self,
        slot: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
        stage: &mut F,
    ) -> Result<&[ModuleSlot]>
    where
        D: Send + Sync + 'static,
        K: 'cfg,
        Resolver: KeyResolver<K, Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            ModuleSlot,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        if !self.session.contains_pending(slot) && self.committed.contains_module(slot) {
            self.session.track(slot, self.committed.generation(slot));
        }
        if self.known_direct_deps(slot).is_none() {
            let needed_len = self.source(slot).needed_len();
            let mut direct_deps = Vec::with_capacity(needed_len);
            for idx in 0..needed_len {
                let key = {
                    let contains_key = |key: &K| self.contains_key(key);
                    let source = self.source(slot);
                    let search = source.search();
                    let needed = source
                        .needed(idx)
                        .expect("DT_NEEDED index must be within the parsed dependency list");
                    let owner_key = self.committed.key(self.committed.entry_key(slot));
                    let loaders =
                        |visitor: &mut LoaderVisitor<'_>| self.visit_loaders(slot, visitor);
                    if let Some(key) = resolver
                        .map_name(needed)
                        .filter(|key| self.contains_key(key))
                    {
                        ResolvedKey::existing(key)
                    } else {
                        let req = DependencyRequest::new(
                            owner_key,
                            search,
                            needed,
                            &self.tokens,
                            &loaders,
                            &contains_key,
                        );
                        resolver.resolve_dependency(&req)?
                    }
                };
                push_dep(&mut direct_deps, stage(self, key, slot, loader)?);
            }
            self.session.set_direct_deps(slot, direct_deps);
        }
        Ok(self
            .known_direct_deps(slot)
            .expect("resolved module must retain its direct dependencies"))
    }

    fn resolve_dependency_graph_with<'cfg, D, Obs, F, M, Exec, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
        mut stage: F,
    ) -> Result<()>
    where
        D: Send + Sync + 'static,
        K: 'cfg,
        Resolver: KeyResolver<K, Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            ModuleSlot,
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

impl<K, D: Send + Sync + 'static, Arch, R, Tls, Meta>
    ResolveContext<'_, K, Arch, RawDynamic<D, Arch, R, Tls>, Tls, Meta>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage<'cfg, Obs, M, Exec, Resolver>(
        &mut self,
        resolved: ResolvedKey<'cfg, K, Arch, Tls>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        K: 'cfg,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
        Resolver: KeyResolver<K, Arch, Tls>,
    {
        match resolved {
            ResolvedKey::Existing(key) => self.existing(&key),
            ResolvedKey::Load { key, reader } => {
                self.ensure_new(&key)?;
                if let Some(slot) = self.reuse_file(&key, reader.file_id()) {
                    return Ok(slot);
                }
                let raw = loader.load_dynamic(reader)?;
                Ok(self.stage_dynamic(key, raw, parent, resolver))
            }
            ResolvedKey::Module { key, module, deps } => {
                self.committed.ensure_domain(module.domain_id())?;
                self.ensure_new(&key)?;
                if let Some(slot) = self.reuse_module(&key, &module) {
                    return Ok(slot);
                }
                let direct_deps = self.stage_module_deps(deps, loader, |ctx, dep, loader| {
                    ctx.stage::<Obs, M, Exec, Resolver>(dep, parent, loader, resolver)
                })?;
                Ok(self.stage_module(key, module, direct_deps, resolver))
            }
        }
    }

    pub(crate) fn resolve_pending<'cfg, Obs, M, Exec, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        K: 'cfg,
        Resolver: KeyResolver<K, Arch, Tls>,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        if !self.contains_pending(root) {
            if self.committed.contains_module(root) {
                self.session.track(root, self.committed.generation(root));
            }
            return Ok(());
        }
        self.resolve_dependency_graph_with(
            root,
            loader,
            resolver,
            |ctx, resolved, parent, loader| ctx.stage(resolved, Some(parent), loader, resolver),
        )
    }
}

impl<K, Arch, Tls, Meta> ResolveContext<'_, K, Arch, ScannedDynamic<Arch>, Tls, Meta>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage<D, Obs, M, Exec, Resolver>(
        &mut self,
        resolved: ResolvedKey<'static, K, Arch, Tls>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        D: Send + Sync + 'static,
        K: 'static,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        Resolver: KeyResolver<K, Arch, Tls>,
    {
        match resolved {
            ResolvedKey::Existing(key) => self.existing(&key),
            ResolvedKey::Load { key, reader } => {
                self.ensure_new(&key)?;
                if let Some(slot) = self.reuse_file(&key, reader.file_id()) {
                    return Ok(slot);
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(ParsePhdrError::MissingDynamicSection.into());
                };
                Ok(self.stage_dynamic(key, module, parent, resolver))
            }
            ResolvedKey::Module { key, module, deps } => {
                self.committed.ensure_domain(module.domain_id())?;
                self.ensure_new(&key)?;
                if let Some(slot) = self.reuse_module(&key, &module) {
                    return Ok(slot);
                }
                let direct_deps = self.stage_module_deps(deps, loader, |ctx, dep, loader| {
                    ctx.stage::<D, Obs, M, Exec, Resolver>(dep, parent, loader, resolver)
                })?;
                Ok(self.stage_module(key, module, direct_deps, resolver))
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<D, Obs, M, Exec, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        D: Send + Sync + 'static,
        K: 'static,
        Resolver: KeyResolver<K, Arch, Tls>,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(
            root,
            loader,
            resolver,
            |ctx, resolved, parent, loader| ctx.stage(resolved, Some(parent), loader, resolver),
        )
    }
}
