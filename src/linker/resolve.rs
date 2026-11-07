use super::{
    resolver::{
        DependencySource, KeyResolver, LoaderVisitor, ResolveRequest, ResolvedDependency,
        ResolvedKey, ResolvedKind,
    },
    session::ResolveSession,
    storage::{CommittedStorage, ModuleKey, ModuleSlot},
};
use crate::{
    LoaderRun, ParsePhdrError, Result,
    arch::NativeArch,
    elf::ElfHeader,
    entity::EntitySet,
    image::{
        ModuleHandle, ModuleSearch, PathTokens, RawDynamic, ScannedDynamic, ScannedElf,
        default_module_search,
    },
    input::{ElfReader, ModuleSourceId},
    memory::{HostRegion, RegionAccess},
    observer::{LinkerObserver, LoadObserver},
    os::Mmap,
    relocation::RelocationArch,
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
    entry_key: &[u8],
) -> (Option<ModuleKey>, Option<ModuleKey>) {
    let path = search.path().as_bytes();
    let path = (path != entry_key).then(|| ModuleKey::from(path));
    let soname = search
        .soname()
        .filter(|soname| *soname != entry_key && Some(*soname) != path.as_deref())
        .map(ModuleKey::from);
    (path, soname)
}

pub(crate) struct ResolveContext<'a, Arch: RelocationArch = NativeArch, P = (), Meta = ()> {
    committed: &'a mut CommittedStorage<Meta, Arch>,
    session: &'a mut ResolveSession<P, Arch>,
    tokens: PathTokens,
}

pub(crate) type LoadResolveContext<'a, D, Arch = NativeArch, R = HostRegion, Tls = (), Meta = ()> =
    ResolveContext<'a, Arch, RawDynamic<D, Arch, R, Tls>, Meta>;

pub(crate) type ScanResolveContext<'a, Arch = NativeArch, Meta = ()> =
    ResolveContext<'a, Arch, ScannedDynamic<Arch>, Meta>;

impl<'a, Arch, P, Meta> ResolveContext<'a, Arch, P, Meta>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<Meta, Arch>,
        session: &'a mut ResolveSession<P, Arch>,
        tokens: PathTokens,
    ) -> Self {
        Self {
            committed,
            session,
            tokens,
        }
    }
}

impl<Arch, P, Meta> ResolveContext<'_, Arch, P, Meta>
where
    Arch: RelocationArch,
    P: DependencySource,
{
    fn known_module(&self, key: &[u8]) -> Option<ModuleSlot> {
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
        let (slot, generation) = self.session.reserve_source(self.committed, source);
        self.session
            .stage_dynamic(slot, generation, entry_key.clone(), payload, loader);
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
        module: ModuleHandle<Arch>,
        direct_deps: Box<[ModuleSlot]>,
    ) -> ModuleSlot {
        let (path, soname) = module
            .search()
            .map(|search| search_aliases(search, &entry_key))
            .unwrap_or_default();
        let (slot, generation) = self
            .session
            .reserve_source(self.committed, module.source_id());
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

    fn stage_with<'cfg>(
        &mut self,
        entry_key: ModuleKey,
        resolved: ResolvedKey<'cfg, Arch>,
        parent: Option<ModuleSlot>,
        materialize: &mut impl FnMut(Box<dyn ElfReader + 'cfg>, ElfHeader<Arch::Layout>) -> Result<P>,
    ) -> Result<ModuleSlot> {
        let (resolved, pinned, aliases) = resolved.into_parts();
        let mut module_deps = None;
        let slot = if let Some(slot) = self.known_module(&entry_key) {
            slot
        } else {
            match resolved {
                ResolvedKind::Load { reader, ehdr } => {
                    if let Some(slot) = self.module_for_source(reader.source_id()) {
                        self.session.bind_key(entry_key, slot);
                        slot
                    } else {
                        let payload = materialize(reader, ehdr)?;
                        self.stage_dynamic(entry_key, payload, parent)
                    }
                }
                ResolvedKind::Module { module, deps } => {
                    self.committed.ensure_domain(module.domain_id())?;
                    if let Some(slot) = self.module_for_source(module.source_id()) {
                        self.session.bind_key(entry_key, slot);
                        slot
                    } else {
                        module_deps = Some(deps);
                        self.stage_module(entry_key, module, Box::default())
                    }
                }
            }
        };
        // Publish names into the pending graph before descending into supplied
        // dependencies, so aliases and cycles resolve to this same instance.
        for alias in aliases {
            self.session.bind_key(alias, slot);
        }
        if let Some(deps) = module_deps {
            let mut direct_deps = Vec::with_capacity(deps.len());
            for ResolvedDependency { key, resolved } in deps {
                let dep = self.stage_with(key, resolved, parent, materialize)?;
                push_dep(&mut direct_deps, dep);
            }
            self.session
                .set_module_deps(slot, direct_deps.into_boxed_slice());
        }
        if pinned {
            self.session.pin(slot);
        }
        Ok(slot)
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
    ) -> Result<ResolvedKey<'cfg, Arch>>
    where
        Resolver: KeyResolver<Arch>,
    {
        let search = caller
            .and_then(|slot| self.search(slot))
            .unwrap_or_else(|| default_module_search());
        let loaders = |visitor: &mut LoaderVisitor<'_>| match caller {
            Some(slot) => self.visit_loaders(slot, visitor),
            None => Ok(()),
        };
        let req = ResolveRequest::root(root, search, &self.tokens, &loaders);
        resolver.resolve(req)
    }

    pub(crate) fn resolve_committed_root<Resolver>(
        &self,
        root: Resolver::Root,
        caller: Option<ModuleSlot>,
        resolver: &Resolver,
    ) -> Result<Option<ModuleSlot>>
    where
        Resolver: KeyResolver<Arch>,
    {
        let resolved = self.resolve_root_input(root, caller, resolver)?;
        let (resolved, _, _) = resolved.into_parts();
        let source = match resolved {
            ResolvedKind::Load { reader, .. } => reader.source_id(),
            ResolvedKind::Module { module, .. } => module.source_id(),
        };
        Ok(self.module_for_source(source))
    }

    fn direct_deps_for<'cfg, Tls: TlsResolver<Arch>, D, Obs, F, M, Resolver>(
        &mut self,
        slot: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
        stage: &mut F,
    ) -> Result<&[ModuleSlot]>
    where
        D: Send + Sync + 'static,
        Resolver: KeyResolver<Arch>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ModuleKey,
            ResolvedKey<'cfg, Arch>,
            ModuleSlot,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
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
                    let existing = self.known_module(needed).or_else(|| {
                        let canonical = resolver.normalize_key(needed);
                        (canonical != needed)
                            .then(|| self.known_module(canonical))
                            .flatten()
                    });
                    if let Some(dep) = existing {
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

    fn resolve_dependency_graph_with<'cfg, Tls: TlsResolver<Arch>, D, Obs, F, M, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
        mut stage: F,
    ) -> Result<()>
    where
        D: Send + Sync + 'static,
        Resolver: KeyResolver<Arch>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ModuleKey,
            ResolvedKey<'cfg, Arch>,
            ModuleSlot,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        ) -> Result<ModuleSlot>,
    {
        if !self.session.contains_pending(root) {
            self.session.track(root, self.committed.generation(root));
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
    ResolveContext<'_, Arch, RawDynamic<D, Arch, R, Tls>, Meta>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn resolve_root<Obs, M, Resolver>(
        &mut self,
        root: Resolver::Root,
        request_key: ModuleKey,
        caller: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        D: Default,
        Resolver: KeyResolver<Arch>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap<Region = R>,
    {
        let resolved = self.resolve_root_input(root, caller, resolver)?;
        let root = self.stage(request_key, resolved, caller, loader)?;
        self.resolve_graph(root, loader, resolver)?;
        Ok(root)
    }

    pub(crate) fn stage<'cfg, Obs, M>(
        &mut self,
        entry_key: ModuleKey,
        resolved: ResolvedKey<'cfg, Arch>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
    ) -> Result<ModuleSlot>
    where
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
    {
        self.stage_with(entry_key, resolved, parent, &mut |reader, ehdr| {
            loader.load_dynamic_with_ehdr(reader, ehdr)
        })
    }

    pub(super) fn resolve_graph<Obs, M, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        Resolver: KeyResolver<Arch>,
        D: Default,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
    {
        self.resolve_dependency_graph_with(
            root,
            loader,
            resolver,
            |ctx, key, resolved, parent, loader| ctx.stage(key, resolved, Some(parent), loader),
        )
    }
}

impl<Arch, Meta> ResolveContext<'_, Arch, ScannedDynamic<Arch>, Meta>
where
    Arch: RelocationArch,
{
    pub(crate) fn resolve_root<Tls: TlsResolver<Arch>, D, Obs, M, Resolver>(
        &mut self,
        root: Resolver::Root,
        request_key: ModuleKey,
        caller: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        D: Default + Send + Sync + 'static,
        Resolver: KeyResolver<Arch>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap,
    {
        let resolved = self.resolve_root_input(root, caller, resolver)?;
        let root = self.stage(request_key, resolved, caller, loader)?;
        self.resolve_graph(root, loader, resolver)?;
        Ok(root)
    }

    pub(crate) fn stage<Tls: TlsResolver<Arch>, D, Obs, M>(
        &mut self,
        entry_key: ModuleKey,
        resolved: ResolvedKey<'static, Arch>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
    ) -> Result<ModuleSlot>
    where
        D: Default + Send + Sync + 'static,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap,
    {
        self.stage_with(entry_key, resolved, parent, &mut |reader, ehdr| {
            let ScannedElf::Dynamic(module) = loader.scan_with_ehdr(reader, ehdr)? else {
                return Err(ParsePhdrError::MissingDynamicSection.into());
            };
            Ok(module)
        })
    }

    fn resolve_graph<Tls: TlsResolver<Arch>, D, Obs, M, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        D: Default + Send + Sync + 'static,
        Resolver: KeyResolver<Arch>,
        Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        M: Mmap,
    {
        self.resolve_dependency_graph_with(
            root,
            loader,
            resolver,
            |ctx, key, resolved, parent, loader| ctx.stage(key, resolved, Some(parent), loader),
        )
    }
}
