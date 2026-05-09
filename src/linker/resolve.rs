use super::{
    request::{DependencyOwner, DependencyRequest, LoadObserver, StagedDynamic, VisibleModules},
    session::{ResolveSession, extend_breadth_first},
    storage::CommittedStorageView,
    view::DependencyGraphView,
};
use crate::{
    LinkerError, Loader, Result, UnresolvedDependencyError,
    image::{RawDynamic, ScannedDynamic, ScannedElf},
    input::ElfReader,
    loader::LoadHook,
    os::Mmap,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

/// A key-resolution result chosen by caller policy.
pub enum ResolvedKey<'cfg, K> {
    /// Reuses a module that is already visible in the current link context.
    Existing(K),
    /// Loads a new module for the provided canonical key and target arch.
    Load {
        key: K,
        reader: Box<dyn ElfReader + 'cfg>,
    },
}

impl<'cfg, K> ResolvedKey<'cfg, K> {
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    #[inline]
    pub fn load(key: K, reader: impl ElfReader + 'cfg) -> Self {
        Self::Load {
            key,
            reader: Box::new(reader),
        }
    }
}

/// Runtime key-resolution policy used by [`super::Linker`].
pub trait KeyResolver<
    'cfg,
    K: Clone,
    D: 'static,
    Meta = (),
    Arch: RelocationArch = crate::arch::NativeArch,
>
{
    fn load_root(&mut self, key: &K) -> Result<ResolvedKey<'cfg, K>>;

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, K, D, Meta, Arch>,
    ) -> Result<Option<ResolvedKey<'cfg, K>>>;
}

pub(crate) struct LoadResolveContext<
    'a,
    K: Clone,
    D: 'static,
    Meta = (),
    V = (),
    Arch: RelocationArch = crate::arch::NativeArch,
> {
    visible: CommittedStorageView<'a, K, D, Meta, Arch>,
    visible_modules: &'a V,
    session: &'a mut ResolveSession<K, RawDynamic<D, Arch>>,
}

pub(crate) struct ScanResolveContext<
    'a,
    K: Clone,
    D: 'static,
    Meta = (),
    V = (),
    Arch: RelocationArch = crate::arch::NativeArch,
> {
    visible: CommittedStorageView<'a, K, D, Meta, Arch>,
    visible_modules: &'a V,
    session: &'a mut ResolveSession<K, ScannedDynamic<Arch>>,
}

impl<'a, K: Clone, D: 'static, Meta, V, Arch> ScanResolveContext<'a, K, D, Meta, V, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        visible: CommittedStorageView<'a, K, D, Meta, Arch>,
        visible_modules: &'a V,
        session: &'a mut ResolveSession<K, ScannedDynamic<Arch>>,
    ) -> Self {
        Self {
            visible,
            visible_modules,
            session,
        }
    }
}

impl<'a, K: Clone, D: 'static, Meta, V, Arch> LoadResolveContext<'a, K, D, Meta, V, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        visible: CommittedStorageView<'a, K, D, Meta, Arch>,
        visible_modules: &'a V,
        session: &'a mut ResolveSession<K, RawDynamic<D, Arch>>,
    ) -> Self {
        Self {
            visible,
            visible_modules,
            session,
        }
    }
}

impl<K, D: 'static, Meta, V, Arch> LoadResolveContext<'_, K, D, Meta, V, Arch>
where
    K: Clone + Ord,
    V: VisibleModules<K, D, Arch>,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn contains_pending(&self, key: &K) -> bool {
        self.session.contains_key(key)
    }

    fn known_direct_deps(&self, key: &K) -> Option<Vec<K>> {
        if self.session.contains_key(key) {
            return None;
        }

        self.visible
            .direct_deps(key)
            .map(|deps| deps.to_vec())
            .or_else(|| self.visible_modules.direct_deps(key).map(Vec::from))
    }

    fn owner<'a>(&'a self, key: &K) -> Option<&'a dyn DependencyOwner>
    where
        K: 'a,
    {
        self.session
            .entries
            .get(key)
            .map(|entry| &entry.payload as &dyn DependencyOwner)
    }

    fn visible_view(&self) -> DependencyGraphView<'_, K, D, Meta, Arch> {
        DependencyGraphView::new_overlay(self.visible, self.session, self.visible_modules)
    }

    fn set_direct_deps(&mut self, key: &K, direct_deps: Vec<K>) {
        let entry = self
            .session
            .entries
            .get_mut(key)
            .expect("session entry must exist for staged key");
        entry.set_direct_deps(direct_deps);
    }

    pub(crate) fn stage_resolved<'cfg, M, H, Tls, O>(
        &mut self,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        observer: &mut O,
    ) -> Result<K>
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
                if self.session.contains_key(&key)
                    || self.visible.contains_key(&key)
                    || self.visible_modules.contains_key(&key)
                {
                    return Ok(key);
                }
                Err(LinkerError::resolver(
                    "resolved existing module is not visible in the current link context",
                )
                .into())
            }
            ResolvedKey::Load { key, reader } => {
                assert!(
                    !self.session.contains_key(&key)
                        && !self.visible.contains_key(&key)
                        && !self.visible_modules.contains_key(&key),
                    "resolved reader produced an already-known key; use ResolvedKey::Existing to reuse a visible module"
                );
                let raw = loader.load_dynamic(reader)?;
                observer.on_staged_dynamic(StagedDynamic::new(&key, &raw))?;
                self.session.insert_entry(key.clone(), raw);
                Ok(key)
            }
        }
    }

    fn resolve_dependency_edge<'cfg>(
        &self,
        key: &K,
        needed_index: usize,
        resolver: &mut impl KeyResolver<'cfg, K, D, Meta, Arch>,
    ) -> Result<ResolvedKey<'cfg, K>>
    where
        K: 'cfg,
    {
        let req = {
            let owner = self
                .owner(key)
                .expect("missing dependency owner while building request");
            DependencyRequest::new(key, owner, Arch::KIND, needed_index, self.visible_view())
        };

        resolver.resolve_dependency(&req)?.ok_or_else(|| {
            LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
                req.owner_name(),
                req.needed(),
            )))
            .into()
        })
    }

    fn direct_deps_for<'cfg, M, H, Tls, O>(
        &mut self,
        key: &K,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'cfg, K, D, Meta, Arch>,
        observer: &mut O,
    ) -> Result<Vec<K>>
    where
        K: 'cfg,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
        O: LoadObserver<K, D, Arch>,
    {
        if let Some(direct_deps) = self.known_direct_deps(key) {
            return Ok(direct_deps);
        }

        let needed_len = self
            .owner(key)
            .expect("missing dependency owner while resolving direct deps")
            .needed_len();
        let mut direct_deps = Vec::with_capacity(needed_len);
        for idx in 0..needed_len {
            let resolved_key = self.resolve_dependency_edge(key, idx, resolver)?;
            let dep_key = self.stage_resolved(resolved_key, loader, observer)?;
            if !direct_deps.contains(&dep_key) {
                direct_deps.push(dep_key);
            }
        }
        self.set_direct_deps(key, direct_deps.clone());
        Ok(direct_deps)
    }

    pub(crate) fn resolve_dependency_graph<'cfg, M, H, Tls, O>(
        &mut self,
        root: K,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'cfg, K, D, Meta, Arch>,
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
        let mut group_order = Vec::new();
        extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for(key, loader, resolver, observer)
        })?;
        self.session.group_order = group_order;
        Ok(())
    }
}

impl<K, D: 'static, Meta, V, Arch> ScanResolveContext<'_, K, D, Meta, V, Arch>
where
    K: Clone + Ord,
    V: VisibleModules<K, D, Arch>,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn contains_pending(&self, key: &K) -> bool {
        self.session.contains_key(key)
    }

    fn known_direct_deps(&self, key: &K) -> Option<Vec<K>> {
        if self.session.contains_key(key) {
            return None;
        }

        self.visible
            .direct_deps(key)
            .map(|deps| deps.to_vec())
            .or_else(|| self.visible_modules.direct_deps(key).map(Vec::from))
    }

    fn owner<'a>(&'a self, key: &K) -> Option<&'a dyn DependencyOwner>
    where
        K: 'a,
    {
        self.session
            .entries
            .get(key)
            .map(|entry| &entry.payload as &dyn DependencyOwner)
    }

    fn visible_view(&self) -> DependencyGraphView<'_, K, D, Meta, Arch> {
        DependencyGraphView::new_overlay(self.visible, self.session, self.visible_modules)
    }

    fn set_direct_deps(&mut self, key: &K, direct_deps: Vec<K>) {
        let entry = self
            .session
            .entries
            .get_mut(key)
            .expect("session entry must exist for staged key");
        entry.set_direct_deps(direct_deps);
    }

    pub(crate) fn stage_resolved<M, H, Tls>(
        &mut self,
        resolved: ResolvedKey<'static, K>,
        loader: &mut Loader<M, H, D, Tls, Arch>,
    ) -> Result<K>
    where
        K: 'static,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        match resolved {
            ResolvedKey::Existing(key) => {
                if self.session.contains_key(&key)
                    || self.visible.contains_key(&key)
                    || self.visible_modules.contains_key(&key)
                {
                    return Ok(key);
                }
                Err(LinkerError::resolver("scan resolver referenced an unknown visible key").into())
            }
            ResolvedKey::Load { key, reader } => {
                if self.session.contains_key(&key)
                    || self.visible.contains_key(&key)
                    || self.visible_modules.contains_key(&key)
                {
                    return Err(LinkerError::resolver(
                        "scan resolver attached metadata to an already-known key; use Existing to reuse it",
                    )
                    .into());
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(crate::ParsePhdrError::MissingDynamicSection.into());
                };
                self.session.insert_entry(key.clone(), module);
                Ok(key)
            }
        }
    }

    fn resolve_dependency_edge(
        &self,
        key: &K,
        needed_index: usize,
        resolver: &mut impl KeyResolver<'static, K, D, Meta, Arch>,
    ) -> Result<ResolvedKey<'static, K>>
    where
        K: 'static,
    {
        let req = {
            let owner = self
                .owner(key)
                .expect("missing dependency owner while building request");
            DependencyRequest::new(key, owner, Arch::KIND, needed_index, self.visible_view())
        };

        resolver.resolve_dependency(&req)?.ok_or_else(|| {
            LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
                req.owner_name(),
                req.needed(),
            )))
            .into()
        })
    }

    fn direct_deps_for<M, H, Tls>(
        &mut self,
        key: &K,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'static, K, D, Meta, Arch>,
    ) -> Result<Vec<K>>
    where
        K: 'static,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        if let Some(direct_deps) = self.known_direct_deps(key) {
            return Ok(direct_deps);
        }

        let needed_len = self
            .owner(key)
            .expect("missing dependency owner while resolving direct deps")
            .needed_len();
        let mut direct_deps = Vec::with_capacity(needed_len);
        for idx in 0..needed_len {
            let resolved_key = self.resolve_dependency_edge(key, idx, resolver)?;
            let dep_key = self.stage_resolved(resolved_key, loader)?;
            if !direct_deps.contains(&dep_key) {
                direct_deps.push(dep_key);
            }
        }
        self.set_direct_deps(key, direct_deps.clone());
        Ok(direct_deps)
    }

    pub(crate) fn resolve_dependency_graph<M, H, Tls>(
        &mut self,
        root: K,
        loader: &mut Loader<M, H, D, Tls, Arch>,
        resolver: &mut impl KeyResolver<'static, K, D, Meta, Arch>,
    ) -> Result<()>
    where
        K: 'static,
        D: Default,
        M: Mmap,
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
    {
        let mut group_order = Vec::new();
        extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for(key, loader, resolver)
        })?;
        self.session.group_order = group_order;
        Ok(())
    }
}
