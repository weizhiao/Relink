use super::{
    resolver::{
        DependencySource, KeyResolver, LoaderVisitor, ResolveRequest, ResolvedDependency,
        ResolvedKey,
    },
    session::ResolveSession,
    storage::{CommittedStorage, ModuleKey, ModuleSlot},
};
use crate::{
    LoaderRun, ParsePhdrError, Result,
    arch::NativeArch,
    entity::EntitySet,
    image::{
        DEFAULT_MODULE_SEARCH, ModuleHandle, ModuleSearch, PathTokens, RawDynamic, ScannedDynamic,
        ScannedElf,
    },
    input::ModuleSourceId,
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

fn search_aliases(
    search: &ModuleSearch,
    entry_key: &str,
) -> (Option<ModuleKey>, Option<ModuleKey>) {
    let path = search.path().as_str();
    let path = (path != entry_key).then(|| ModuleKey::from(path));
    let soname = search
        .soname()
        .filter(|soname| *soname != entry_key && Some(*soname) != path.as_deref())
        .map(ModuleKey::from);
    (path, soname)
}

pub(crate) struct ResolveContext<
    'a,
    Arch: RelocationArch = NativeArch,
    P = (),
    Tls: TlsResolver<Arch> = (),
    Meta = (),
> {
    committed: &'a mut CommittedStorage<Meta, Arch, Tls>,
    session: &'a mut ResolveSession<P, Arch, Tls>,
    tokens: PathTokens,
}

pub(crate) type LoadResolveContext<'a, D, Arch = NativeArch, R = HostRegion, Tls = (), Meta = ()> =
    ResolveContext<'a, Arch, RawDynamic<D, Arch, R, Tls>, Tls, Meta>;

pub(crate) type ScanResolveContext<'a, Arch = NativeArch, Tls = (), Meta = ()> =
    ResolveContext<'a, Arch, ScannedDynamic<Arch>, Tls, Meta>;

impl<'a, Arch, P, Tls, Meta> ResolveContext<'a, Arch, P, Tls, Meta>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<Meta, Arch, Tls>,
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

impl<Arch, P, Tls, Meta> ResolveContext<'_, Arch, P, Tls, Meta>
where
    Arch: RelocationArch,
    P: DependencySource,
    Tls: TlsResolver<Arch>,
{
    fn known_module(&self, key: &str) -> Option<ModuleSlot> {
        self.committed
            .module_for_key(key)
            .or_else(|| self.session.module_for_key(key))
    }

    fn module_for_source(&self, id: ModuleSourceId) -> Option<ModuleSlot> {
        self.committed
            .module_for_source(id)
            .or_else(|| self.session.module_for_source(id))
    }

    pub(crate) fn stage_dynamic(
        &mut self,
        entry_key: ModuleKey,
        payload: P,
        loader: Option<ModuleSlot>,
    ) -> ModuleSlot {
        let source = payload.source_id();
        let (path, soname) = search_aliases(payload.search(), &entry_key);
        let slot = self.committed.alloc_module();
        let generation = self.committed.generation(slot);
        self.session
            .stage_dynamic(slot, generation, entry_key.clone(), payload, loader);
        self.session.stage_source(source, slot);
        self.session.bind_key(entry_key, slot);
        if let Some(path) = path {
            self.session.bind_key(path, slot);
        }
        if let Some(soname) = soname {
            self.session.bind_key(soname, slot);
        }
        slot
    }

    fn stage_module(
        &mut self,
        entry_key: ModuleKey,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
    ) -> ModuleSlot {
        let (path, soname) = module
            .search()
            .map(|search| search_aliases(search, &entry_key))
            .unwrap_or_default();
        let slot = self.committed.alloc_module();
        let generation = self.committed.generation(slot);
        self.session
            .stage_module(slot, generation, entry_key.clone(), module, direct_deps);
        self.session.bind_key(entry_key, slot);
        if let Some(path) = path {
            self.session.bind_key(path, slot);
        }
        if let Some(soname) = soname {
            self.session.bind_key(soname, slot);
        }
        slot
    }

    fn stage_module_deps<'cfg, D, Obs, F, M, Exec>(
        &mut self,
        deps: Vec<ResolvedDependency<'cfg, Arch, Tls>>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        mut stage: F,
    ) -> Result<Box<[ModuleSlot]>>
    where
        D: Send + Sync + 'static,
        Obs: LoadObserver<D, Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ModuleKey,
            ResolvedKey<'cfg, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        let mut direct_deps = Vec::with_capacity(deps.len());
        for ResolvedDependency { key, resolved } in deps {
            push_dep(&mut direct_deps, stage(self, key, resolved, loader)?);
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

    fn resolve_root_input<'cfg, Resolver>(
        &self,
        root: Resolver::Root,
        caller: Option<ModuleSlot>,
        resolver: &Resolver,
    ) -> Result<ResolvedKey<'cfg, Arch, Tls>>
    where
        Resolver: KeyResolver<Arch, Tls>,
    {
        let search = caller
            .and_then(|slot| self.search(slot))
            .unwrap_or(&DEFAULT_MODULE_SEARCH);
        let loaders = |visitor: &mut LoaderVisitor<'_>| match caller {
            Some(slot) => self.visit_loaders(slot, visitor),
            None => Ok(()),
        };
        let req = ResolveRequest::root(root, search, &self.tokens, &loaders);
        resolver.resolve(req)
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
        Resolver: KeyResolver<Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ModuleKey,
            ResolvedKey<'cfg, Arch, Tls>,
            ModuleSlot,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        if !self.session.contains_pending(slot) && self.committed.contains_module(slot) {
            self.session.track(slot, self.committed.generation(slot));
            if self.session.direct_deps(slot).is_none() {
                let direct_deps = self
                    .committed
                    .module(slot)
                    .expect("committed module must remain available while resolving")
                    .direct_deps()
                    .to_vec()
                    .into_boxed_slice();
                self.session.cache_committed_deps(slot, direct_deps);
            }
        }
        if self.known_direct_deps(slot).is_none() {
            let needed_len = self.source(slot).needed_len();
            let mut direct_deps = Vec::with_capacity(needed_len);
            for idx in 0..needed_len {
                let resolved = {
                    let source = self.source(slot);
                    let search = source.search();
                    let needed = source
                        .needed(idx)
                        .expect("DT_NEEDED index must be within the parsed dependency list");
                    if let Some(dep) = self.known_module(needed) {
                        push_dep(&mut direct_deps, dep);
                        continue;
                    }
                    let loaders =
                        |visitor: &mut LoaderVisitor<'_>| self.visit_loaders(slot, visitor);
                    let req = ResolveRequest::dependency(needed, search, &self.tokens, &loaders);
                    let resolved = resolver.resolve(req)?;
                    (ModuleKey::from(needed), resolved)
                };
                let (request_key, resolved) = resolved;
                let dep = stage(self, request_key, resolved, slot, loader)?;
                push_dep(&mut direct_deps, dep);
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
        Resolver: KeyResolver<Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ModuleKey,
            ResolvedKey<'cfg, Arch, Tls>,
            ModuleSlot,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<ModuleSlot>,
    {
        if !self.session.contains_pending(root) {
            if self.committed.contains_module(root) {
                self.session.track(root, self.committed.generation(root));
            }
            return Ok(());
        }

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

impl<D: Send + Sync + 'static, Arch, R, Tls, Meta>
    ResolveContext<'_, Arch, RawDynamic<D, Arch, R, Tls>, Tls, Meta>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn resolve_root<Obs, M, Exec, Resolver>(
        &mut self,
        root: Resolver::Root,
        request_key: ModuleKey,
        caller: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        D: Default,
        Resolver: KeyResolver<Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        let resolved = self.resolve_root_input(root, caller, resolver)?;
        let root = self.stage(request_key, resolved, caller, loader)?;
        self.resolve_graph(root, loader, resolver)?;
        Ok(root)
    }

    pub(crate) fn stage<'cfg, Obs, M, Exec>(
        &mut self,
        entry_key: ModuleKey,
        resolved: ResolvedKey<'cfg, Arch, Tls>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<ModuleSlot>
    where
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        if let Some(slot) = self.known_module(&entry_key) {
            return Ok(slot);
        }

        match resolved {
            ResolvedKey::Load(reader) => {
                if let Some(slot) = self.module_for_source(reader.source_id()) {
                    self.session.bind_key(entry_key, slot);
                    return Ok(slot);
                }
                let raw = loader.load_dynamic(reader)?;
                Ok(self.stage_dynamic(entry_key, raw, parent))
            }
            ResolvedKey::Module { module, deps } => {
                self.committed.ensure_domain(module.domain_id())?;
                if let Some(slot) = self.module_for_source(module.source_id()) {
                    self.session.bind_key(entry_key, slot);
                    return Ok(slot);
                }
                let direct_deps =
                    self.stage_module_deps(deps, loader, |ctx, key, dep, loader| {
                        ctx.stage::<Obs, M, Exec>(key, dep, parent, loader)
                    })?;
                Ok(self.stage_module(entry_key, module, direct_deps))
            }
        }
    }

    pub(super) fn resolve_graph<Obs, M, Exec, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        Resolver: KeyResolver<Arch, Tls>,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(
            root,
            loader,
            resolver,
            |ctx, key, resolved, parent, loader| ctx.stage(key, resolved, Some(parent), loader),
        )
    }
}

impl<Arch, Tls, Meta> ResolveContext<'_, Arch, ScannedDynamic<Arch>, Tls, Meta>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn resolve_root<D, Obs, M, Exec, Resolver>(
        &mut self,
        root: Resolver::Root,
        request_key: ModuleKey,
        caller: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        D: Default + Send + Sync + 'static,
        Resolver: KeyResolver<Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        let resolved = self.resolve_root_input(root, caller, resolver)?;
        let root = self.stage(request_key, resolved, caller, loader)?;
        self.resolve_graph(root, loader, resolver)?;
        Ok(root)
    }

    pub(crate) fn stage<D, Obs, M, Exec>(
        &mut self,
        entry_key: ModuleKey,
        resolved: ResolvedKey<'static, Arch, Tls>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<ModuleSlot>
    where
        D: Default + Send + Sync + 'static,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        if let Some(slot) = self.known_module(&entry_key) {
            return Ok(slot);
        }

        match resolved {
            ResolvedKey::Load(reader) => {
                if let Some(slot) = self.module_for_source(reader.source_id()) {
                    self.session.bind_key(entry_key, slot);
                    return Ok(slot);
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(ParsePhdrError::MissingDynamicSection.into());
                };
                Ok(self.stage_dynamic(entry_key, module, parent))
            }
            ResolvedKey::Module { module, deps } => {
                self.committed.ensure_domain(module.domain_id())?;
                if let Some(slot) = self.module_for_source(module.source_id()) {
                    self.session.bind_key(entry_key, slot);
                    return Ok(slot);
                }
                let direct_deps =
                    self.stage_module_deps(deps, loader, |ctx, key, dep, loader| {
                        ctx.stage::<D, Obs, M, Exec>(key, dep, parent, loader)
                    })?;
                Ok(self.stage_module(entry_key, module, direct_deps))
            }
        }
    }

    fn resolve_graph<D, Obs, M, Exec, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        D: Default + Send + Sync + 'static,
        Resolver: KeyResolver<Arch, Tls>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(
            root,
            loader,
            resolver,
            |ctx, key, resolved, parent, loader| ctx.stage(key, resolved, Some(parent), loader),
        )
    }
}
