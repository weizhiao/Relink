use super::{
    request::{DependencyOwner, DependencyRequest},
    session::{ResolveSession, collect_unique_deps, extend_breadth_first},
    storage::CommittedStorageView,
    view::DependencyGraphView,
};
use crate::{
    LinkerError, Loader, Result, UnresolvedDependencyError,
    image::{RawDylib, ScannedDylib},
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
pub trait KeyResolver<'cfg, K, D: 'static> {
    /// Resolves one root key to either an already-visible key or a loadable reader.
    fn load_root(&mut self, key: &K) -> Result<ResolvedKey<'cfg, K>>;

    /// Resolves one `DT_NEEDED` edge during recursive dependency loading or
    /// scan-first discovery.
    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, K, D>,
    ) -> Result<Option<ResolvedKey<'cfg, K>>>;
}

pub(crate) trait ResolveStage<'cfg, K, D: 'static, P, M, H, Tls>
where
    K: Ord,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    fn stage_resolved(
        visible: CommittedStorageView<'_, K, D>,
        session: &mut ResolveSession<K, P>,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls>,
    ) -> Result<K>;
}

pub(crate) struct LoadStage;

impl<'cfg, K, D: 'static, M, H, Tls> ResolveStage<'cfg, K, D, RawDylib<D>, M, H, Tls> for LoadStage
where
    K: Clone + Ord,
    D: Default,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    fn stage_resolved(
        visible: CommittedStorageView<'_, K, D>,
        session: &mut ResolveSession<K, RawDylib<D>>,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls>,
    ) -> Result<K> {
        match resolved {
            ResolvedKey::Existing(key) => {
                if session.contains_key(&key) || visible.contains_key(&key) {
                    return Ok(key);
                }
                Err(LinkerError::resolver(
                    "resolved existing module is not visible in the current link context",
                )
                .into())
            }
            ResolvedKey::Load(key, reader) => {
                let raw = loader.load_dylib_impl(reader)?;
                assert!(
                    !session.contains_key(&key) && !visible.contains_key(&key),
                    "resolved reader produced an already-known key; use ResolvedKey::Existing to reuse a visible module"
                );
                session.insert_entry(key.clone(), raw);
                Ok(key)
            }
        }
    }
}

pub(crate) struct ScanStage;

impl<K, D: 'static, M, H, Tls> ResolveStage<'static, K, D, ScannedDylib<D>, M, H, Tls> for ScanStage
where
    K: Clone + Ord,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    fn stage_resolved(
        visible: CommittedStorageView<'_, K, D>,
        session: &mut ResolveSession<K, ScannedDylib<D>>,
        resolved: ResolvedKey<'static, K>,
        loader: &mut Loader<M, H, D, Tls>,
    ) -> Result<K> {
        match resolved {
            ResolvedKey::Existing(key) => {
                if session.contains_key(&key) || visible.contains_key(&key) {
                    return Ok(key);
                }
                Err(LinkerError::resolver("scan resolver referenced an unknown visible key").into())
            }
            ResolvedKey::Load(key, reader) => {
                if session.contains_key(&key) || visible.contains_key(&key) {
                    return Err(LinkerError::resolver(
                        "scan resolver attached metadata to an already-known key; use Existing to reuse it",
                    )
                    .into());
                }
                let module = loader.scan_dylib_impl(reader)?;
                session.insert_entry(key.clone(), module);
                Ok(key)
            }
        }
    }
}

pub(crate) struct SessionResolveContext<'a, K, D: 'static, P, S> {
    visible: CommittedStorageView<'a, K, D>,
    session: &'a mut ResolveSession<K, P>,
    _stage: PhantomData<S>,
}

pub(crate) type LoadResolveContext<'a, K, D> =
    SessionResolveContext<'a, K, D, RawDylib<D>, LoadStage>;
pub(crate) type ScanResolveContext<'a, K, D> =
    SessionResolveContext<'a, K, D, ScannedDylib<D>, ScanStage>;

impl<'a, K, D: 'static, P, S> SessionResolveContext<'a, K, D, P, S> {
    #[inline]
    pub(crate) fn new(
        visible: CommittedStorageView<'a, K, D>,
        session: &'a mut ResolveSession<K, P>,
    ) -> Self {
        Self {
            visible,
            session,
            _stage: PhantomData,
        }
    }
}

impl<K, D: 'static, P, S> SessionResolveContext<'_, K, D, P, S>
where
    K: Ord,
    P: DependencyOwner,
{
    pub(crate) fn contains_pending(&self, key: &K) -> bool {
        self.session.contains_key(key)
    }

    fn visible_committed(&self) -> CommittedStorageView<'_, K, D> {
        self.visible
    }

    fn known_direct_deps(&self, key: &K) -> Option<&[K]> {
        self.visible_committed().direct_deps(key)
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

    fn visible_view(&self) -> DependencyGraphView<'_, K, D> {
        DependencyGraphView::new_overlay(self.visible, self.session)
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
        resolver: &mut impl KeyResolver<'cfg, K, D>,
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

impl<'cfg, K, D: 'static, P, S> SessionResolveContext<'_, K, D, P, S>
where
    K: Clone + Ord + 'cfg,
    P: DependencyOwner,
{
    fn direct_deps_for<M, H, Tls>(
        &mut self,
        key: &K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
    ) -> Result<Vec<K>>
    where
        S: ResolveStage<'cfg, K, D, P, M, H, Tls>,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        if let Some(direct_deps) = self.known_direct_deps(key) {
            let direct_deps = direct_deps.to_vec();
            self.set_direct_deps(key, direct_deps.clone());
            return Ok(direct_deps);
        }

        let needed_len = self
            .owner(key)
            .expect("missing dependency owner while resolving direct deps")
            .needed_len();
        let direct_deps = collect_unique_deps(needed_len, |idx| {
            let resolved_key = self.resolve_dependency_edge(key, idx, resolver)?;
            self.stage_resolved(resolved_key, loader)
        })?;
        self.set_direct_deps(key, direct_deps.clone());
        Ok(direct_deps)
    }

    pub(crate) fn resolve_dependency_graph<M, H, Tls>(
        &mut self,
        root: K,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'cfg, K, D>,
    ) -> Result<()>
    where
        S: ResolveStage<'cfg, K, D, P, M, H, Tls>,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut group_order = mem::take(&mut self.session.group_order);
        let result = extend_breadth_first(&mut group_order, root, |key| {
            self.direct_deps_for(key, loader, resolver)
        });
        self.session.group_order = group_order;
        result
    }

    pub(crate) fn stage_resolved<M, H, Tls>(
        &mut self,
        resolved: ResolvedKey<'cfg, K>,
        loader: &mut Loader<M, H, D, Tls>,
    ) -> Result<K>
    where
        S: ResolveStage<'cfg, K, D, P, M, H, Tls>,
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        S::stage_resolved(self.visible, self.session, resolved, loader)
    }
}
