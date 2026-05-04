use super::{
    request::{DependencyOwner, DependencyRequest, LoadObserver, StagedDylib, VisibleModules},
    session::{ResolveSession, collect_unique_deps, extend_breadth_first},
    storage::CommittedStorageView,
    view::DependencyGraphView,
};
use crate::{
    LinkerError, Loader, ParsePhdrError, Result, UnresolvedDependencyError,
    image::{RawDynamic, ScannedDynamic, ScannedElf},
    input::ElfReader,
    loader::LoadHook,
    os::Mmap,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;
use core::mem;

/// A key-resolution result chosen by caller policy.
pub enum ResolvedKey<'cfg, K> {
    /// Reuses a module that is already visible in the current link context.
    Existing(K),
    /// Loads a new module for the provided canonical key using the context's loader.
    Load(K, Box<dyn ElfReader + 'cfg>),
}

impl<'cfg, K> ResolvedKey<'cfg, K> {
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    #[inline]
    pub fn load(key: K, reader: impl ElfReader + 'cfg) -> Self {
        Self::Load(key, Box::new(reader))
    }
}

/// Runtime key-resolution policy used by [`super::Linker`].
///
/// The caller owns key semantics. A request may start with an application key
/// and resolve either to an already visible key or to a concrete reader that
/// [`crate::Loader`] should load next.
pub trait KeyResolver<'cfg, K: Clone, D: 'static, Meta = ()> {
    /// Resolves one root key to either an already-visible key or a loadable reader.
    fn load_root(&mut self, key: &K) -> Result<ResolvedKey<'cfg, K>>;

    /// Resolves one `DT_NEEDED` edge during recursive dependency loading or
    /// scan-first discovery.
    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, K, D, Meta>,
    ) -> Result<Option<ResolvedKey<'cfg, K>>>;
}

pub(crate) trait ResolveStage<'cfg, K, D: 'static, Meta, P, M, H, Tls, O, V>
where
    K: Clone + Ord,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
    O: LoadObserver<K, D>,
    V: VisibleModules<K, D>,
{
    fn stage_resolved(
        visible: CommittedStorageView<'_, K, D, Meta>,
        visible_modules: &V,
        session: &mut ResolveSession<K, P>,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls>,
        observer: &mut O,
    ) -> Result<K>;
}

pub(crate) struct LoadStage;

impl<'cfg, K, D: 'static, Meta, M, H, Tls, O, V>
    ResolveStage<'cfg, K, D, Meta, RawDynamic<D>, M, H, Tls, O, V> for LoadStage
where
    K: Clone + Ord,
    D: Default,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
    O: LoadObserver<K, D>,
    V: VisibleModules<K, D>,
{
    fn stage_resolved(
        visible: CommittedStorageView<'_, K, D, Meta>,
        visible_modules: &V,
        session: &mut ResolveSession<K, RawDynamic<D>>,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls>,
        observer: &mut O,
    ) -> Result<K> {
        match resolved {
            ResolvedKey::Existing(key) => {
                if session.contains_key(&key)
                    || visible.contains_key(&key)
                    || visible_modules.contains_key(&key)
                {
                    return Ok(key);
                }
                Err(LinkerError::resolver(
                    "resolved existing module is not visible in the current link context",
                )
                .into())
            }
            ResolvedKey::Load(key, reader) => {
                let raw = loader.load_dynamic(reader)?;
                assert!(
                    !session.contains_key(&key)
                        && !visible.contains_key(&key)
                        && !visible_modules.contains_key(&key),
                    "resolved reader produced an already-known key; use ResolvedKey::Existing to reuse a visible module"
                );
                observer.on_staged_dylib(StagedDylib::new(&key, &raw))?;
                session.insert_entry(key.clone(), raw);
                Ok(key)
            }
        }
    }
}

pub(crate) struct ScanStage;

impl<K, D: 'static, Meta, M, H, Tls, O, V>
    ResolveStage<'static, K, D, Meta, ScannedDynamic, M, H, Tls, O, V> for ScanStage
where
    K: Clone + Ord,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
    O: LoadObserver<K, D>,
    V: VisibleModules<K, D>,
{
    fn stage_resolved(
        visible: CommittedStorageView<'_, K, D, Meta>,
        visible_modules: &V,
        session: &mut ResolveSession<K, ScannedDynamic>,
        resolved: ResolvedKey<'static, K>,
        loader: &mut Loader<M, H, D, Tls>,
        _observer: &mut O,
    ) -> Result<K> {
        match resolved {
            ResolvedKey::Existing(key) => {
                if session.contains_key(&key)
                    || visible.contains_key(&key)
                    || visible_modules.contains_key(&key)
                {
                    return Ok(key);
                }
                Err(LinkerError::resolver("scan resolver referenced an unknown visible key").into())
            }
            ResolvedKey::Load(key, reader) => {
                if session.contains_key(&key)
                    || visible.contains_key(&key)
                    || visible_modules.contains_key(&key)
                {
                    return Err(LinkerError::resolver(
                        "scan resolver attached metadata to an already-known key; use Existing to reuse it",
                    )
                    .into());
                }
                let ScannedElf::Dynamic(module) = loader.scan(reader)? else {
                    return Err(ParsePhdrError::MissingDynamicSection.into());
                };
                session.insert_entry(key.clone(), module);
                Ok(key)
            }
        }
    }
}

pub(crate) struct SessionResolveContext<'a, K: Clone, D: 'static, Meta, P, S, V> {
    visible: CommittedStorageView<'a, K, D, Meta>,
    visible_modules: &'a V,
    session: &'a mut ResolveSession<K, P>,
    _stage: PhantomData<S>,
}

pub(crate) type LoadResolveContext<'a, K, D, Meta = (), V = ()> =
    SessionResolveContext<'a, K, D, Meta, RawDynamic<D>, LoadStage, V>;
pub(crate) type ScanResolveContext<'a, K, D, Meta = (), V = ()> =
    SessionResolveContext<'a, K, D, Meta, ScannedDynamic, ScanStage, V>;

impl<'a, K: Clone, D: 'static, Meta, P, S, V> SessionResolveContext<'a, K, D, Meta, P, S, V> {
    #[inline]
    pub(crate) fn new(
        visible: CommittedStorageView<'a, K, D, Meta>,
        visible_modules: &'a V,
        session: &'a mut ResolveSession<K, P>,
    ) -> Self {
        Self {
            visible,
            visible_modules,
            session,
            _stage: PhantomData,
        }
    }
}

impl<K, D: 'static, Meta, P, S, V> SessionResolveContext<'_, K, D, Meta, P, S, V>
where
    K: Clone + Ord,
    P: DependencyOwner,
    V: VisibleModules<K, D>,
{
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

    fn visible_view(&self) -> DependencyGraphView<'_, K, D, Meta> {
        DependencyGraphView::new_overlay(self.visible, self.session, self.visible_modules)
    }

    fn set_direct_deps(&mut self, key: &K, direct_deps: Vec<K>) {
        if let Some(entry) = self.session.entries.get_mut(key) {
            entry.set_direct_deps(direct_deps);
        }
    }

    fn resolve_dependency_edge<'cfg>(
        &self,
        key: &K,
        needed_index: usize,
        resolver: &mut impl KeyResolver<'cfg, K, D, Meta>,
    ) -> Result<ResolvedKey<'cfg, K>>
    where
        K: 'cfg,
    {
        let req = {
            let owner = self
                .owner(key)
                .expect("missing dependency owner while building request");
            DependencyRequest::new(key, owner, needed_index, self.visible_view())
        };

        resolver.resolve_dependency(&req)?.ok_or_else(|| {
            LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
                req.owner_name(),
                req.needed(),
            )))
            .into()
        })
    }
}

impl<'cfg, K, D: 'static, Meta, P, S, V> SessionResolveContext<'_, K, D, Meta, P, S, V>
where
    K: Clone + Ord + 'cfg,
    P: DependencyOwner,
    V: VisibleModules<K, D>,
{
    fn direct_deps_for<M, H, Tls, O>(
        &mut self,
        key: &K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D, Meta>,
        observer: &mut O,
    ) -> Result<Vec<K>>
    where
        S: ResolveStage<'cfg, K, D, Meta, P, M, H, Tls, O, V>,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
        O: LoadObserver<K, D>,
        V: VisibleModules<K, D>,
    {
        if let Some(direct_deps) = self.known_direct_deps(key) {
            self.set_direct_deps(key, direct_deps.clone());
            return Ok(direct_deps);
        }

        let needed_len = self
            .owner(key)
            .expect("missing dependency owner while resolving direct deps")
            .needed_len();
        let direct_deps = collect_unique_deps(needed_len, |idx| {
            let resolved_key = self.resolve_dependency_edge(key, idx, resolver)?;
            self.stage_resolved(resolved_key, loader, observer)
        })?;
        self.set_direct_deps(key, direct_deps.clone());
        Ok(direct_deps)
    }

    pub(crate) fn resolve_dependency_graph<M, H, Tls, O>(
        &mut self,
        root: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D, Meta>,
        observer: &mut O,
    ) -> Result<()>
    where
        S: ResolveStage<'cfg, K, D, Meta, P, M, H, Tls, O, V>,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
        O: LoadObserver<K, D>,
        V: VisibleModules<K, D>,
    {
        let mut group_order = mem::take(&mut self.session.group_order);
        let result = extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for(key, loader, resolver, observer)
        });
        self.session.group_order = group_order;
        result
    }

    pub(crate) fn stage_resolved<M, H, Tls, O>(
        &mut self,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls>,
        observer: &mut O,
    ) -> Result<K>
    where
        S: ResolveStage<'cfg, K, D, Meta, P, M, H, Tls, O, V>,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
        O: LoadObserver<K, D>,
    {
        S::stage_resolved(
            self.visible,
            self.visible_modules,
            self.session,
            resolved,
            loader,
            observer,
        )
    }
}
