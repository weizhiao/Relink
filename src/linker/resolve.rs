use super::{
    resolver::{
        DependencyOwner, DependencyRequest, KeyResolver, ResolvedKey, RootRequest, SearchOwner,
    },
    session::{GraphEntry, ModuleEntry, ResolveSession},
    storage::{CommittedStorage, KeySlot},
};
use crate::{
    LinkResolverError, LinkerError, LoaderRun, ParsePhdrError, Result,
    arch::NativeArch,
    image::{ModuleHandle, RawDynamic, ScannedDynamic, ScannedElf},
    memory::{HostRegion, RegionAccess},
    observer::{LinkerObserver, LoadObserver},
    os::Mmap,
    relocation::RelocationArch,
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, boxed::Box, collections::BTreeSet, vec::Vec};
use core::borrow::Borrow;

fn walk_breadth_first<K, E, F>(queue: &mut Vec<K>, mut visit: F) -> core::result::Result<(), E>
where
    K: Clone,
    F: FnMut(&K, &mut Vec<K>) -> core::result::Result<(), E>,
{
    let mut cursor = 0;

    while cursor < queue.len() {
        let key = queue[cursor].clone();
        cursor += 1;
        visit(&key, queue)?;
    }

    Ok(())
}

fn extend_breadth_first<K, E, F>(
    group_order: &mut Vec<K>,
    root: K,
    mut direct_deps: F,
) -> core::result::Result<(), E>
where
    K: Clone + Ord,
    F: FnMut(&K) -> core::result::Result<Vec<K>, E>,
{
    let mut visited = BTreeSet::new();
    visited.insert(root.clone());
    group_order.push(root);

    walk_breadth_first(group_order, |key, queue| {
        for dep_key in direct_deps(key)? {
            if visited.insert(dep_key.clone()) {
                queue.push(dep_key);
            }
        }
        Ok(())
    })
}

pub(crate) struct ResolveContext<
    'a,
    K: Clone,
    D: Send + Sync + 'static,
    Meta = (),
    Arch: RelocationArch = NativeArch,
    P = (),
    Tls: TlsResolver<Arch> = (),
> {
    committed: &'a mut CommittedStorage<K, D, Meta, Arch, Tls>,
    session: &'a mut ResolveSession<P, Arch, Tls>,
}

pub(crate) type LoadResolveContext<
    'a,
    K,
    D,
    Meta = (),
    Arch = NativeArch,
    R = HostRegion,
    Tls = (),
> = ResolveContext<'a, K, D, Meta, Arch, RawDynamic<D, Arch, R, Tls>, Tls>;

pub(crate) type ScanResolveContext<'a, K, D, Meta = (), Arch = NativeArch, Tls = ()> =
    ResolveContext<'a, K, D, Meta, Arch, ScannedDynamic<Arch>, Tls>;

impl<'a, K: Clone, D: Send + Sync + 'static, Meta, Arch, P, Tls>
    ResolveContext<'a, K, D, Meta, Arch, P, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<K, D, Meta, Arch, Tls>,
        session: &'a mut ResolveSession<P, Arch, Tls>,
    ) -> Self {
        Self { committed, session }
    }
}

impl<K, D: Send + Sync + 'static, Meta, Arch, P, Tls> ResolveContext<'_, K, D, Meta, Arch, P, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    P: DependencyOwner,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn contains_pending(&self, slot: KeySlot) -> bool {
        self.session.contains_pending(slot)
    }

    #[inline]
    fn contains_key<Q, R, Obs>(&self, key: &Q, observer: &Obs) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
        R: RegionAccess,
        Obs: LinkerObserver<K, D, Arch, R, Tls> + ?Sized,
    {
        if let Some(slot) = self.committed.key_slot_for(key)
            && (self.session.contains_pending(slot)
                || self
                    .committed
                    .module_for_key(slot)
                    .is_some_and(|slot| self.committed.contains_module(slot)))
        {
            return true;
        }

        observer.contains_visible(key)
    }

    fn pending_or_committed<Q>(&self, key: &Q) -> Option<KeySlot>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let slot = self.committed.key_slot_for(key)?;
        (self.session.contains_pending(slot)
            || self
                .committed
                .module_for_key(slot)
                .is_some_and(|slot| self.committed.contains_module(slot)))
        .then_some(slot)
    }

    fn stage_module_handle(
        &mut self,
        key: K,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[KeySlot]>,
    ) -> Result<KeySlot> {
        self.committed.ensure_domain(module.domain_id())?;
        let slot = self.intern_key(key);
        self.session
            .module_handles
            .insert(slot, ModuleEntry::new(module, direct_deps));
        Ok(slot)
    }

    fn stage_existing_key<Q, R, Obs>(&mut self, key: K, observer: &Obs) -> Result<KeySlot>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
        R: RegionAccess,
        Obs: LinkerObserver<K, D, Arch, R, Tls> + ?Sized,
    {
        if let Some(slot) = self.pending_or_committed(key.borrow()) {
            return Ok(slot);
        }

        let visible_key = key.borrow();
        let module = observer
            .visible_module(visible_key)
            .ok_or_else(|| LinkerError::resolver(LinkResolverError::ExistingKeyNotVisible))?;
        let (module, direct_deps) = module.into_parts();

        let direct_dep_keys = direct_deps.into_vec();
        let direct_deps = direct_dep_keys
            .iter()
            .cloned()
            .map(|key| self.intern_key(key))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let slot = self.stage_module_handle(key, module, direct_deps)?;
        for dep in direct_dep_keys {
            self.stage_existing_key::<Q, R, Obs>(dep, observer)?;
        }
        Ok(slot)
    }

    fn stage_module_deps<'cfg, Obs, F, M, Exec>(
        &mut self,
        deps: Vec<ResolvedKey<'cfg, K, Arch, Tls>>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        mut stage: F,
    ) -> Result<Box<[KeySlot]>>
    where
        Obs: LoadObserver<D, Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<KeySlot>,
    {
        let mut direct_deps = Vec::with_capacity(deps.len());
        for dep in deps {
            let dep_id = stage(self, dep, loader)?;
            if !direct_deps.contains(&dep_id) {
                direct_deps.push(dep_id);
            }
        }
        Ok(direct_deps.into_boxed_slice())
    }

    fn intern_key(&mut self, key: K) -> KeySlot {
        self.committed.intern_key(key)
    }

    fn key(&self, slot: KeySlot) -> &K {
        self.committed.key(slot)
    }

    fn known_direct_deps(&self, slot: KeySlot) -> Option<Vec<KeySlot>> {
        if let Some(entry) = self.session.dynamics.get(&slot) {
            return entry.direct_deps().map(<[KeySlot]>::to_vec);
        }
        if let Some(entry) = self.session.module_handles.get(&slot) {
            return Some(entry.direct_deps().to_vec());
        }

        if let Some(module_slot) = self.committed.module_for_key(slot) {
            let module = self.committed.module(module_slot).present()?;
            return Some(module.direct_deps().iter().map(|edge| edge.key()).collect());
        }

        None
    }

    fn owner(&self, slot: KeySlot) -> &dyn DependencyOwner {
        self.session
            .dynamics
            .get(&slot)
            .expect("dependency owner must be present for a staged dynamic module")
            .payload() as &dyn DependencyOwner
    }

    fn set_direct_deps(&mut self, slot: KeySlot, direct_deps: Vec<KeySlot>) {
        let entry = self
            .session
            .dynamics
            .get_mut(&slot)
            .expect("session entry must exist for staged key");
        entry.set_direct_deps(direct_deps);
    }

    fn resolve_dependency_edge<'cfg, Q, R, Obs>(
        &self,
        slot: KeySlot,
        needed_index: usize,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
        observer: &Obs,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        R: RegionAccess,
        Obs: LinkerObserver<K, D, Arch, R, Tls> + ?Sized,
    {
        let contains_key = |key: &Q| self.contains_key::<Q, R, Obs>(key, observer);
        let owner = self.owner(slot);
        let owner_key = self.key(slot);
        let req = DependencyRequest::new(owner_key, owner, needed_index, &contains_key);
        resolver.resolve_dependency(&req)
    }

    pub(crate) fn resolve_root<'cfg, Q, R, Obs>(
        &self,
        key: &K,
        owner: Option<SearchOwner<'_>>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
        observer: &Obs,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        R: RegionAccess,
        Obs: LinkerObserver<K, D, Arch, R, Tls> + ?Sized,
    {
        let contains_key = |key: &Q| self.contains_key::<Q, R, Obs>(key, observer);
        let req = RootRequest::new(key, owner, &contains_key);
        resolver.load_root(&req)
    }

    fn direct_deps_for<'cfg, Obs, F, M, Exec, Q>(
        &mut self,
        slot: KeySlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
        stage: &mut F,
    ) -> Result<Vec<KeySlot>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Obs: LinkerObserver<K, D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<KeySlot>,
    {
        if let Some(direct_deps) = self.known_direct_deps(slot) {
            return Ok(direct_deps);
        }

        let needed_len = self.owner(slot).needed_len();
        let mut direct_deps = Vec::with_capacity(needed_len);
        for idx in 0..needed_len {
            let key = self.resolve_dependency_edge::<Q, M::Region, Obs>(
                slot,
                idx,
                resolver,
                &loader.observer,
            )?;
            let dep_id = stage(self, key, loader)?;
            if !direct_deps.contains(&dep_id) {
                direct_deps.push(dep_id);
            }
        }
        self.set_direct_deps(slot, direct_deps.clone());
        Ok(direct_deps)
    }

    fn resolve_dependency_graph_with<'cfg, Obs, F, M, Exec, Q>(
        &mut self,
        root: KeySlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
        mut stage: F,
    ) -> Result<()>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Obs: LinkerObserver<K, D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        ) -> Result<KeySlot>,
    {
        let mut group_order = Vec::new();
        extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for(*key, loader, resolver, &mut stage)
        })?;
        self.session.group_order = group_order;
        Ok(())
    }
}

impl<K, D: Send + Sync + 'static, Meta, Arch, R, Tls>
    ResolveContext<'_, K, D, Meta, Arch, RawDynamic<D, Arch, R, Tls>, Tls>
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
    ) -> Result<KeySlot>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<K, D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                self.stage_existing_key::<Q, M::Region, Obs>(key, &loader.observer)
            }
            ResolvedKey::Load { key, reader } => {
                if self.contains_key::<Q, M::Region, Obs>(key.borrow(), &loader.observer) {
                    return Err(LinkerError::resolver(LinkResolverError::NewKeyAlreadyKnown).into());
                }
                let raw = loader.load_dynamic(reader)?;
                let slot = self.intern_key(key);
                self.session.dynamics.insert(slot, GraphEntry::new(raw));
                Ok(slot)
            }
            ResolvedKey::Module { key, module, deps } => {
                if self.contains_key::<Q, M::Region, Obs>(key.borrow(), &loader.observer) {
                    return Err(LinkerError::resolver(LinkResolverError::NewKeyAlreadyKnown).into());
                }

                let direct_deps = self.stage_module_deps(deps, loader, |ctx, dep, loader| {
                    ctx.stage::<Obs, M, Exec, Q>(dep, loader)
                })?;
                self.stage_module_handle(key, module, direct_deps)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<'cfg, Obs, M, Exec, Q>(
        &mut self,
        root: KeySlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
    ) -> Result<()>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<K, D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage(resolved, loader)
        })
    }
}

impl<K, D: Send + Sync + 'static, Meta, Arch, Tls>
    ResolveContext<'_, K, D, Meta, Arch, ScannedDynamic<Arch>, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage<Obs, M, Exec, Q>(
        &mut self,
        resolved: ResolvedKey<'static, K, Arch, Tls>,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
    ) -> Result<KeySlot>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<K, D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                self.stage_existing_key::<Q, M::Region, Obs>(key, &loader.observer)
            }
            ResolvedKey::Load { key, reader } => {
                if self.contains_key::<Q, M::Region, Obs>(key.borrow(), &loader.observer) {
                    return Err(LinkerError::resolver(LinkResolverError::NewKeyAlreadyKnown).into());
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(ParsePhdrError::MissingDynamicSection.into());
                };
                let slot = self.intern_key(key);
                self.session.dynamics.insert(slot, GraphEntry::new(module));
                Ok(slot)
            }
            ResolvedKey::Module { key, module, deps } => {
                if self.contains_key::<Q, M::Region, Obs>(key.borrow(), &loader.observer) {
                    return Err(LinkerError::resolver(LinkResolverError::NewKeyAlreadyKnown).into());
                }

                let direct_deps = self.stage_module_deps(deps, loader, |ctx, dep, loader| {
                    ctx.stage::<Obs, M, Exec, Q>(dep, loader)
                })?;
                self.stage_module_handle(key, module, direct_deps)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<Obs, M, Exec, Q>(
        &mut self,
        root: KeySlot,
        loader: &mut LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>,
        resolver: &impl KeyResolver<K, Arch, Q, Tls>,
    ) -> Result<()>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        D: Default,
        Obs: LinkerObserver<K, D, Arch, M::Region, Tls> + LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage(resolved, loader)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::walk_breadth_first;
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    #[test]
    fn breadth_first_walk_visits_siblings_before_descendants() {
        let graph = BTreeMap::from([
            ("A", vec!["B", "C"]),
            ("B", vec!["D"]),
            ("C", Vec::new()),
            ("D", Vec::new()),
        ]);
        let mut queue = vec!["A"];
        let mut visited = Vec::new();

        walk_breadth_first(&mut queue, |key, queue| {
            visited.push(*key);
            queue.extend(graph.get(key).into_iter().flatten().copied());
            Ok::<_, ()>(())
        })
        .unwrap();

        assert_eq!(visited, vec!["A", "B", "C", "D"]);
    }
}
