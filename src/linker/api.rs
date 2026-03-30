use super::{
    plan::LinkPlan,
    request::{DependencyRequest, RelocationRequest},
    view::LinkContextView,
};
use crate::{
    Result,
    image::{LoadedCore, RawDylib, ScannedDylib},
};
use alloc::boxed::Box;

/// A module chosen by a loader or dependency resolver.
pub enum ResolvedModule<K, D: 'static> {
    /// Reuses a module that is already present in the current context.
    ///
    /// Resolvers can return this after consulting [`DependencyRequest::context`]
    /// or their own session-local bookkeeping when they want cache-first
    /// behavior.
    Existing(K),
    /// Introduces a newly mapped but not yet relocated shared object.
    Raw(K, RawDylib<D>),
    /// Introduces a dependency that is already relocated and ready to use.
    ///
    /// Resolvers may also attach the dependency's canonical direct-dependency
    /// keys so the current load can preserve breadth-first group order without
    /// re-deriving it later.
    Loaded(K, LoadedCore<D>, Box<[K]>),
}

impl<K, D> ResolvedModule<K, D> {
    /// Creates a raw module result.
    #[inline]
    pub fn new_raw(key: K, dylib: RawDylib<D>) -> Self {
        Self::Raw(key, dylib)
    }

    /// Creates an already-loaded module result with its canonical direct
    /// dependencies.
    #[inline]
    pub fn new_loaded(key: K, dylib: LoadedCore<D>, direct_deps: Box<[K]>) -> Self {
        Self::Loaded(key, dylib, direct_deps)
    }

    /// Reuses an existing key from the current context.
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    /// Returns the selected key.
    #[inline]
    pub fn key(&self) -> &K {
        match self {
            Self::Existing(key) | Self::Raw(key, _) | Self::Loaded(key, _, _) => key,
        }
    }
}

/// Resolver callbacks for root modules and `DT_NEEDED` edges.
///
/// A resolver turns a caller-defined key into a concrete root module, and can
/// also resolve dependency requests produced while linking that root.
///
/// The root-loading and dependency-resolution steps are kept together because
/// they usually share the same cache lookup, canonicalization, and probing
/// logic.
///
/// A root load turns a caller-defined key into a concrete module selected for the
/// current [`LinkContext`]. It may canonicalize the key by returning a
/// different [`ResolvedModule::key()`] than the requested one.
pub trait ModuleResolver<K, D: 'static> {
    /// Loads one module entry point identified by `key`.
    fn load(&mut self, key: &K) -> Result<ResolvedModule<K, D>>;

    /// Resolves one dependency request.
    ///
    /// Returning `Ok(None)` means the resolver deliberately did not resolve the
    /// dependency. Returning `Err` means the resolver itself failed.
    fn resolve(
        &mut self,
        req: &DependencyRequest<'_, K, D>,
    ) -> Result<Option<ResolvedModule<K, D>>>;
}

/// Relocation callbacks for newly mapped modules discovered during `load()`.
///
/// A relocator receives each raw module after dependency resolution has fixed
/// its direct dependency set and established the currently visible load scope.
///
/// For ad-hoc use, any closure `FnMut(RelocationRequest) -> Result<LoadedCore>`
/// also implements this trait.
pub trait ModuleRelocator<K, D: 'static> {
    /// Relocates one newly mapped module into its ready-to-use loaded form.
    fn relocate(&mut self, req: RelocationRequest<'_, K, D>) -> Result<LoadedCore<D>>;
}

impl<K, D: 'static, F> ModuleRelocator<K, D> for F
where
    F: for<'a> FnMut(RelocationRequest<'a, K, D>) -> Result<LoadedCore<D>>,
{
    #[inline]
    fn relocate(&mut self, req: RelocationRequest<'_, K, D>) -> Result<LoadedCore<D>> {
        (self)(req)
    }
}

/// A single materialization request emitted after scan-time planning.
pub struct MaterializationRequest<'a, K, D: 'static> {
    key: &'a K,
    module: &'a ScannedDylib<D>,
    direct_deps: &'a [K],
    plan: &'a LinkPlan<K, D>,
    context: LinkContextView<'a, K, D>,
}

impl<'a, K, D: 'static> MaterializationRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        module: &'a ScannedDylib<D>,
        direct_deps: &'a [K],
        plan: &'a LinkPlan<K, D>,
        context: LinkContextView<'a, K, D>,
    ) -> Self {
        Self {
            key,
            module,
            direct_deps,
            plan,
            context,
        }
    }

    /// Returns the selected key for the module being materialized.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the scanned metadata for the module being materialized.
    #[inline]
    pub fn module(&self) -> &'a ScannedDylib<D> {
        self.module
    }

    /// Returns the canonical direct dependencies of this module.
    #[inline]
    pub fn direct_deps(&self) -> &'a [K] {
        self.direct_deps
    }

    /// Returns the full pre-map link plan.
    #[inline]
    pub fn plan(&self) -> &'a LinkPlan<K, D> {
        self.plan
    }

    /// Returns the already visible loaded modules in the current context.
    #[inline]
    pub fn context(&self) -> LinkContextView<'a, K, D> {
        self.context
    }
}

/// Materialization callbacks for turning a scanned module into a raw or loaded one.
///
/// The scan-first path keeps the dependency graph in [`LinkPlan`], so
/// materializers must preserve the planned key and should treat
/// [`MaterializationRequest::direct_deps`] as authoritative. Any direct
/// dependency list attached to [`ResolvedModule::Loaded`] is ignored when
/// staging scan-planned modules.
pub trait ModuleMaterializer<K, D: 'static> {
    /// Produces the concrete module representation selected for this plan node.
    fn materialize(
        &mut self,
        req: MaterializationRequest<'_, K, D>,
    ) -> Result<ResolvedModule<K, D>>;
}

impl<K, D: 'static, F> ModuleMaterializer<K, D> for F
where
    F: for<'a> FnMut(MaterializationRequest<'a, K, D>) -> Result<ResolvedModule<K, D>>,
{
    #[inline]
    fn materialize(
        &mut self,
        req: MaterializationRequest<'_, K, D>,
    ) -> Result<ResolvedModule<K, D>> {
        (self)(req)
    }
}
