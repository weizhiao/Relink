use super::{
    request::{DependencyOwner, DependencyRequest, RootRequest, VisibleModules},
    resolver::{KeyResolver, ResolvedKey},
    session::{GraphEntry, ModuleEntry, ResolveSession},
    storage::{CommittedStorage, KeyId},
};
use crate::{
    LinkerError, Loader, Result,
    image::{RawDynamic, ScannedDynamic, ScannedElf},
    memory::RegionAccess,
    observer::LoadObserver,
    os::Mmap,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, collections::BTreeSet, vec::Vec};
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
    D: 'static,
    Meta = (),
    V = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    P = (),
    Tls: TlsResolver<Arch> = (),
> {
    committed: &'a mut CommittedStorage<K, D, Meta, Arch, Tls>,
    visible_modules: &'a V,
    session: &'a mut ResolveSession<P, Arch, Tls>,
}

pub(crate) type LoadResolveContext<
    'a,
    K,
    D,
    Meta = (),
    V = (),
    Arch = crate::arch::NativeArch,
    R = crate::memory::HostRegion,
    Tls = (),
> = ResolveContext<'a, K, D, Meta, V, Arch, RawDynamic<D, Arch, R, Tls>, Tls>;

pub(crate) type ScanResolveContext<
    'a,
    K,
    D,
    Meta = (),
    V = (),
    Arch = crate::arch::NativeArch,
    Tls = (),
> = ResolveContext<'a, K, D, Meta, V, Arch, ScannedDynamic<Arch>, Tls>;

impl<'a, K: Clone, D: 'static, Meta, V, Arch, P, Tls>
    ResolveContext<'a, K, D, Meta, V, Arch, P, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        committed: &'a mut CommittedStorage<K, D, Meta, Arch, Tls>,
        visible_modules: &'a V,
        session: &'a mut ResolveSession<P, Arch, Tls>,
    ) -> Self {
        Self {
            committed,
            visible_modules,
            session,
        }
    }
}

impl<K, D: 'static, Meta, V, Arch, P, Tls> ResolveContext<'_, K, D, Meta, V, Arch, P, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    P: DependencyOwner,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn contains_pending(&self, id: KeyId) -> bool {
        self.session.contains_pending(id)
    }

    #[inline]
    fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(id) = self.committed.key_id(key)
            && (self.session.contains_pending(id) || self.committed.contains(id))
        {
            return true;
        }

        self.visible_modules.contains(key)
    }

    fn intern_key(&mut self, key: K) -> KeyId {
        self.committed.intern_key(key)
    }

    fn key(&self, id: KeyId) -> Option<&K> {
        self.committed.key(id)
    }

    fn known_direct_deps<Q>(&mut self, id: KeyId) -> Option<Vec<KeyId>>
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        if let Some(entry) = self.session.dynamics.get(&id) {
            return entry.direct_deps().map(<[KeyId]>::to_vec);
        }
        if let Some(entry) = self.session.module_handles.get(&id) {
            return Some(entry.direct_deps().to_vec());
        }

        if let Some(direct_deps) = self.committed.direct_deps_by_key(id) {
            return Some(direct_deps.to_vec());
        }

        let direct_deps = {
            let key = self.committed.key(id)?;
            self.visible_modules.direct_deps(key.borrow())?
        };
        Some(
            direct_deps
                .into_vec()
                .into_iter()
                .map(|key| self.intern_key(key))
                .collect(),
        )
    }

    fn owner(&self, id: KeyId) -> Option<&dyn DependencyOwner> {
        self.session
            .dynamics
            .get(&id)
            .map(|entry| entry.payload() as &dyn DependencyOwner)
    }

    fn set_direct_deps(&mut self, id: KeyId, direct_deps: Vec<KeyId>) {
        let entry = self
            .session
            .dynamics
            .get_mut(&id)
            .expect("session entry must exist for staged key");
        entry.set_direct_deps(direct_deps);
    }

    fn resolve_dependency_edge<'cfg, Q>(
        &self,
        id: KeyId,
        needed_index: usize,
        resolver: &mut impl KeyResolver<'cfg, K, Arch, Q, Tls>,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let contains_key = |key: &Q| self.contains_key(key);
        let owner = self.owner(id).ok_or_else(|| {
            LinkerError::resolver("dependency owner is missing while building request")
        })?;
        let owner_key = self
            .key(id)
            .expect("dependency owner id must resolve to an interned key");
        let req = DependencyRequest::new(owner_key, owner, needed_index, &contains_key);
        resolver.resolve_dependency(&req)
    }

    pub(crate) fn resolve_root<'cfg, Q>(
        &self,
        key: &K,
        resolver: &mut impl KeyResolver<'cfg, K, Arch, Q, Tls>,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
    {
        let contains_key = |key: &Q| self.contains_key(key);
        let req = RootRequest::new(key, &contains_key);
        resolver.load_root(&req)
    }

    fn direct_deps_for<'cfg, Obs, F, M, Q>(
        &mut self,
        id: KeyId,
        loader: &mut Loader<Obs, D, Tls, Arch, M>,
        resolver: &mut impl KeyResolver<'cfg, K, Arch, Q, Tls>,
        stage: &mut F,
    ) -> Result<Vec<KeyId>>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
        Obs: LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut Loader<Obs, D, Tls, Arch, M>,
        ) -> Result<KeyId>,
    {
        if let Some(direct_deps) = self.known_direct_deps(id) {
            return Ok(direct_deps);
        }

        let needed_len = self
            .owner(id)
            .ok_or_else(|| {
                LinkerError::resolver("dependency owner is missing while resolving direct deps")
            })?
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

    fn resolve_dependency_graph_with<'cfg, Obs, F, M, Q>(
        &mut self,
        root: KeyId,
        loader: &mut Loader<Obs, D, Tls, Arch, M>,
        resolver: &mut impl KeyResolver<'cfg, K, Arch, Q, Tls>,
        mut stage: F,
    ) -> Result<()>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
        Obs: LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
        F: FnMut(
            &mut Self,
            ResolvedKey<'cfg, K, Arch, Tls>,
            &mut Loader<Obs, D, Tls, Arch, M>,
        ) -> Result<KeyId>,
    {
        let mut group_order = Vec::new();
        extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for(*key, loader, resolver, &mut stage)
        })?;
        self.session.group_order = group_order;
        Ok(())
    }
}

impl<K, D: 'static, Meta, V, Arch, R, Tls>
    ResolveContext<'_, K, D, Meta, V, Arch, RawDynamic<D, Arch, R, Tls>, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage_resolved<'cfg, Obs, M, Q>(
        &mut self,
        resolved: ResolvedKey<'cfg, K, Arch, Tls>,
        loader: &mut Loader<Obs, D, Tls, Arch, M>,
    ) -> Result<KeyId>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
        D: Default,
        Obs: LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                if self.contains_key(key.borrow()) {
                    return Ok(self.intern_key(key));
                }
                Err(LinkerError::resolver(
                    "resolved existing module is not visible in the current link context",
                )
                .into())
            }
            ResolvedKey::Load { key, reader } => {
                if self.contains_key(key.borrow()) {
                    return Err(LinkerError::resolver(
                        "resolved reader produced an already-known key; use Existing to reuse it",
                    )
                    .into());
                }
                let raw = loader.load_dynamic(reader)?;
                let id = self.intern_key(key);
                self.session.dynamics.insert(id, GraphEntry::new(raw));
                Ok(id)
            }
            ResolvedKey::Module { key, module, deps } => {
                if self.contains_key(key.borrow()) {
                    return Err(LinkerError::resolver(
                        "resolved module handle produced an already-known key",
                    )
                    .into());
                }

                let mut direct_deps = Vec::with_capacity(deps.len());
                for dep in deps {
                    let dep_id = self.stage_resolved(dep, loader)?;
                    if !direct_deps.contains(&dep_id) {
                        direct_deps.push(dep_id);
                    }
                }

                let id = self.intern_key(key);
                self.session
                    .module_handles
                    .insert(id, ModuleEntry::new(module, direct_deps.into_boxed_slice()));
                Ok(id)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<'cfg, Obs, M, Q>(
        &mut self,
        root: KeyId,
        loader: &mut Loader<Obs, D, Tls, Arch, M>,
        resolver: &mut impl KeyResolver<'cfg, K, Arch, Q, Tls>,
    ) -> Result<()>
    where
        K: 'cfg + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
        D: Default,
        Obs: LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap<Region = R>,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage_resolved(resolved, loader)
        })
    }
}

impl<K, D: 'static, Meta, V, Arch, Tls>
    ResolveContext<'_, K, D, Meta, V, Arch, ScannedDynamic<Arch>, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn stage_resolved<Obs, M, Q>(
        &mut self,
        resolved: ResolvedKey<'static, K, Arch, Tls>,
        loader: &mut Loader<Obs, D, Tls, Arch, M>,
    ) -> Result<KeyId>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
        D: Default,
        Obs: LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                if self.contains_key(key.borrow()) {
                    return Ok(self.intern_key(key));
                }
                Err(LinkerError::resolver("scan resolver referenced an unknown visible key").into())
            }
            ResolvedKey::Load { key, reader } => {
                if self.contains_key(key.borrow()) {
                    return Err(LinkerError::resolver(
                        "scan resolver attached metadata to an already-known key; use Existing to reuse it",
                    )
                    .into());
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(crate::ParsePhdrError::MissingDynamicSection.into());
                };
                let id = self.intern_key(key);
                self.session.dynamics.insert(id, GraphEntry::new(module));
                Ok(id)
            }
            ResolvedKey::Module { key, module, deps } => {
                if self.contains_key(key.borrow()) {
                    return Err(LinkerError::resolver(
                        "scan resolver produced an already-known module key",
                    )
                    .into());
                }

                let mut direct_deps = Vec::with_capacity(deps.len());
                for dep in deps {
                    let dep_id = self.stage_resolved(dep, loader)?;
                    if !direct_deps.contains(&dep_id) {
                        direct_deps.push(dep_id);
                    }
                }

                let id = self.intern_key(key);
                self.session
                    .module_handles
                    .insert(id, ModuleEntry::new(module, direct_deps.into_boxed_slice()));
                Ok(id)
            }
        }
    }

    pub(crate) fn resolve_dependency_graph<Obs, M, Q>(
        &mut self,
        root: KeyId,
        loader: &mut Loader<Obs, D, Tls, Arch, M>,
        resolver: &mut impl KeyResolver<'static, K, Arch, Q, Tls>,
    ) -> Result<()>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        V: VisibleModules<K, Arch, Q, Tls>,
        D: Default,
        Obs: LoadObserver<D, Arch>,
        Tls: TlsResolver<Arch>,
        M: Mmap,
    {
        self.resolve_dependency_graph_with(root, loader, resolver, |ctx, resolved, loader| {
            ctx.stage_resolved(resolved, loader)
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
