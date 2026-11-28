use super::{
    resolver::{
        KeyResolver, LoaderVisitor, ResolveRequest, ResolvedDependency, ResolvedKey, ResolvedKind,
    },
    session::ResolveSession,
    storage::{CommittedStorage, ModuleKey, ModuleSlot},
};
use crate::{
    LoaderRun, Result,
    entity::EntitySet,
    image::{ModuleHandle, ModuleSearch, PathTokens, RawDynamic, default_module_search},
    input::ModuleSourceId,
    memory::RegionAccess,
    observer::LoadObserver,
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

pub(super) struct ResolveContext<
    'a,
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    Meta,
> {
    committed: &'a mut CommittedStorage<Meta, Arch>,
    session: &'a mut ResolveSession<D, Arch, R, Tls>,
    tokens: PathTokens,
}

impl<'a, D, Arch, R, Tls, Meta> ResolveContext<'a, D, Arch, R, Tls, Meta>
where
    D: Default + Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) fn new(
        committed: &'a mut CommittedStorage<Meta, Arch>,
        session: &'a mut ResolveSession<D, Arch, R, Tls>,
        tokens: PathTokens,
    ) -> Self {
        Self {
            committed,
            session,
            tokens,
        }
    }

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

    pub(super) fn stage_dynamic(
        &mut self,
        entry_key: ModuleKey,
        payload: RawDynamic<D, Arch, R, Tls>,
        loader: Option<ModuleSlot>,
    ) -> ModuleSlot {
        let source = payload.state().instance_id().source_id();
        let (path, soname) = search_aliases(&payload.search, &entry_key);
        let (slot, generation) = self.session.reserve_source(self.committed, source, loader);
        self.session
            .stage_dynamic(slot, generation, entry_key.clone(), payload);
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
        parent: Option<ModuleSlot>,
    ) -> ModuleSlot {
        let (path, soname) = module
            .search()
            .map(|search| search_aliases(search, &entry_key))
            .unwrap_or_default();
        let (slot, generation) =
            self.session
                .reserve_source(self.committed, module.source_id(), parent);
        self.session
            .stage_module(slot, generation, entry_key.clone(), module, Box::default());
        self.session.bind_key(entry_key, slot);
        if let Some(path) = path {
            self.session.bind_key(path, slot);
        }
        if let Some(soname) = soname {
            self.session.bind_key(soname, slot);
        }
        slot
    }

    fn stage<Obs, M>(
        &mut self,
        entry_key: ModuleKey,
        resolved: ResolvedKey<'_, Arch>,
        parent: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
    ) -> Result<ModuleSlot>
    where
        Obs: LoadObserver<D, Arch>,
        M: Mmap<Region = R>,
    {
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
                        let payload = loader.load_dynamic_with_ehdr(reader, ehdr)?;
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
                        self.stage_module(entry_key, module, parent)
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
                let dep = self.stage(key, resolved, Some(slot), loader)?;
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

    fn source(&self, slot: ModuleSlot) -> &RawDynamic<D, Arch, R, Tls> {
        self.session
            .dynamic_payload(slot)
            .expect("dependency source must be present for a staged dynamic module")
    }

    fn search(&self, slot: ModuleSlot) -> Option<&ModuleSearch> {
        self.session
            .dynamic_payload(slot)
            .map(|raw| &raw.search)
            .or_else(|| self.session.staged_module(slot)?.search())
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
            let Some(loader) = self
                .session
                .loader(slot)
                .or_else(|| self.committed.module(slot)?.loader())
            else {
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

    pub(super) fn resolve_committed_root<Resolver>(
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

    fn direct_deps_for<Obs, M, Resolver>(
        &mut self,
        slot: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<&[ModuleSlot]>
    where
        Resolver: KeyResolver<Arch>,
        Obs: LoadObserver<D, Arch>,
        M: Mmap<Region = R>,
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
            let needed_len = self.source(slot).needed_libs().len();
            let mut direct_deps = Vec::with_capacity(needed_len);
            for idx in 0..needed_len {
                let (request_key, resolved) = {
                    let source = self.source(slot);
                    let search = &source.search;
                    let needed = source.needed_libs()[idx];
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
                let dep = self.stage(request_key, resolved, Some(slot), loader)?;
                push_dep(&mut direct_deps, dep);
            }
            self.session.set_direct_deps(slot, direct_deps);
        }
        Ok(self
            .known_direct_deps(slot)
            .expect("resolved module must retain its direct dependencies"))
    }

    pub(super) fn resolve_graph<Obs, M, Resolver>(
        &mut self,
        root: ModuleSlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<()>
    where
        Resolver: KeyResolver<Arch>,
        Obs: LoadObserver<D, Arch>,
        M: Mmap<Region = R>,
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
            for &dep in self.direct_deps_for(slot, loader, resolver)? {
                if visited.insert(dep) {
                    group_order.push(dep);
                }
            }
        }
        self.session.set_group_order(group_order);
        Ok(())
    }

    pub(super) fn resolve_root<Obs, M, Resolver>(
        &mut self,
        root: Resolver::Root,
        request_key: ModuleKey,
        caller: Option<ModuleSlot>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M>,
        resolver: &Resolver,
    ) -> Result<ModuleSlot>
    where
        Resolver: KeyResolver<Arch>,
        Obs: LoadObserver<D, Arch>,
        M: Mmap<Region = R>,
    {
        let resolved = self.resolve_root_input(root, caller, resolver)?;
        let root = self.stage(request_key, resolved, caller, loader)?;
        self.resolve_graph(root, loader, resolver)?;
        Ok(root)
    }
}
