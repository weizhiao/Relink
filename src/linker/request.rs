use super::view::DependencyGraphView;
use crate::{
    Result,
    image::{LoadedCore, RawDylib, ScannedDylib},
    relocation::BindingMode,
    sync::Arc,
};
use alloc::boxed::Box;

/// Common metadata needed while resolving one dependency edge.
pub trait DependencyOwner {
    fn name(&self) -> &str;
    fn rpath(&self) -> Option<&str>;
    fn runpath(&self) -> Option<&str>;
    fn interp(&self) -> Option<&str>;
    fn needed_len(&self) -> usize;
    fn needed_lib(&self, index: usize) -> Option<&str>;
}

impl<D: 'static> DependencyOwner for RawDylib<D> {
    #[inline]
    fn name(&self) -> &str {
        self.name()
    }

    #[inline]
    fn rpath(&self) -> Option<&str> {
        self.rpath()
    }

    #[inline]
    fn runpath(&self) -> Option<&str> {
        self.runpath()
    }

    #[inline]
    fn interp(&self) -> Option<&str> {
        self.interp()
    }

    #[inline]
    fn needed_len(&self) -> usize {
        self.needed_libs().len()
    }

    #[inline]
    fn needed_lib(&self, index: usize) -> Option<&str> {
        self.needed_libs().get(index).copied()
    }
}

impl DependencyOwner for ScannedDylib {
    #[inline]
    fn name(&self) -> &str {
        self.name()
    }

    #[inline]
    fn rpath(&self) -> Option<&str> {
        self.rpath()
    }

    #[inline]
    fn runpath(&self) -> Option<&str> {
        self.runpath()
    }

    #[inline]
    fn interp(&self) -> Option<&str> {
        self.interp()
    }

    #[inline]
    fn needed_len(&self) -> usize {
        self.needed_libs().len()
    }

    #[inline]
    fn needed_lib(&self, index: usize) -> Option<&str> {
        self.needed_lib(index)
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K: Clone, D: 'static, M = ()> {
    owner_key: &'a K,
    owner: &'a dyn DependencyOwner,
    needed_index: usize,
    visible: DependencyGraphView<'a, K, D, M>,
}

impl<'a, K: Clone, D: 'static, M> DependencyRequest<'a, K, D, M> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        owner: &'a dyn DependencyOwner,
        needed_index: usize,
        visible: DependencyGraphView<'a, K, D, M>,
    ) -> Self {
        Self {
            owner_key,
            owner,
            needed_index,
            visible,
        }
    }

    /// Returns the key of the owner module.
    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns the owner module.
    #[inline]
    pub fn owner(&self) -> &'a dyn DependencyOwner {
        self.owner
    }

    /// Returns the owner module name.
    #[inline]
    pub fn owner_name(&self) -> &'a str {
        self.owner.name()
    }

    /// Returns the current `DT_NEEDED` string.
    #[inline]
    pub fn needed(&self) -> &'a str {
        self.owner
            .needed_lib(self.needed_index)
            .expect("DT_NEEDED index out of bounds")
    }

    /// Returns the index of the current `DT_NEEDED` entry.
    #[inline]
    pub fn needed_index(&self) -> usize {
        self.needed_index
    }

    /// Returns the owner's `DT_RPATH`.
    #[inline]
    pub fn rpath(&self) -> Option<&'a str> {
        self.owner.rpath()
    }

    /// Returns the owner's `DT_RUNPATH`.
    #[inline]
    pub fn runpath(&self) -> Option<&'a str> {
        self.owner.runpath()
    }

    /// Returns the owner's `PT_INTERP`.
    #[inline]
    pub fn interp(&self) -> Option<&'a str> {
        self.owner.interp()
    }

    /// Returns whether `key` is already visible in the current dependency graph.
    #[inline]
    pub fn is_visible(&self, key: &K) -> bool
    where
        K: Ord,
    {
        self.visible.contains_key(key)
    }
}

/// Read-only modules that should be visible to a link operation without being
/// committed into its local [`LinkContext`](super::LinkContext).
///
/// This is useful for callers that already have process-global or staged
/// modules elsewhere and want the linker to resolve against them without first
/// cloning those modules into the per-load context.
pub trait VisibleModules<K: Clone, D: 'static> {
    /// Returns whether `key` is visible to dependency resolution.
    fn contains_key(&self, _key: &K) -> bool {
        false
    }

    /// Returns the canonical direct dependency keys for a visible module.
    fn direct_deps(&self, _key: &K) -> Option<Box<[K]>> {
        None
    }

    /// Returns the loaded module for relocation-scope construction or a root
    /// that resolves entirely from the visible overlay.
    fn loaded(&self, _key: &K) -> Option<LoadedCore<D>> {
        None
    }
}

impl<K: Clone, D: 'static> VisibleModules<K, D> for () {}

impl<K: Clone, D: 'static, V> VisibleModules<K, D> for &V
where
    V: VisibleModules<K, D> + ?Sized,
{
    #[inline]
    fn contains_key(&self, key: &K) -> bool {
        (**self).contains_key(key)
    }

    #[inline]
    fn direct_deps(&self, key: &K) -> Option<Box<[K]>> {
        (**self).direct_deps(key)
    }

    #[inline]
    fn loaded(&self, key: &K) -> Option<LoadedCore<D>> {
        (**self).loaded(key)
    }
}

/// A mapped but unrelocated dylib observed during a link operation.
///
/// This event fires after a [`RawDylib`] has been materialized and before it is
/// inserted into the linker's pending session. The object is not relocated yet,
/// so observers must not treat it as a ready-to-run module. Callers that create
/// placeholder [`LoadedCore`] values from `raw().core()` are responsible for the
/// safety contract of [`LoadedCore::from_core`].
pub struct StagedDylib<'a, K, D: 'static> {
    key: &'a K,
    raw: &'a RawDylib<D>,
}

impl<'a, K, D: 'static> StagedDylib<'a, K, D> {
    #[inline]
    pub(crate) fn new(key: &'a K, raw: &'a RawDylib<D>) -> Self {
        Self { key, raw }
    }

    /// Returns the canonical key selected for the staged module.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the mapped but unrelocated shared object.
    #[inline]
    pub fn raw(&self) -> &'a RawDylib<D> {
        self.raw
    }
}

/// Observer for modules staged by [`super::Linker`].
pub trait LoadObserver<K, D: 'static> {
    /// Called when a new [`RawDylib`] is mapped but before relocation starts.
    fn on_staged_dylib(&mut self, _event: StagedDylib<'_, K, D>) -> Result<()> {
        Ok(())
    }
}

impl<K, D: 'static> LoadObserver<K, D> for () {}

impl<K, D: 'static, F> LoadObserver<K, D> for F
where
    F: for<'a> FnMut(StagedDylib<'a, K, D>) -> Result<()>,
{
    #[inline]
    fn on_staged_dylib(&mut self, event: StagedDylib<'_, K, D>) -> Result<()> {
        self(event)
    }
}

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<'a, K, D: 'static> {
    key: &'a K,
    raw: RawDylib<D>,
    scope: &'a Arc<[LoadedCore<D>]>,
}

impl<'a, K, D: 'static> RelocationRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(key: &'a K, raw: RawDylib<D>, scope: &'a Arc<[LoadedCore<D>]>) -> Self {
        Self { key, raw, scope }
    }

    /// Returns the key selected for the module being relocated.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the raw module being relocated.
    #[inline]
    pub fn raw(&self) -> &RawDylib<D> {
        &self.raw
    }

    /// Returns the batch-start relocation scope snapshot.
    ///
    /// Pending-group modules appear here as placeholder `LoadedCore` values
    /// until the load session commits them into the stable context.
    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D>] {
        self.scope
    }

    /// Returns the batch-start relocation scope as a shared owner.
    #[inline]
    pub fn shared_scope(&self) -> &Arc<[LoadedCore<D>]> {
        self.scope
    }

    /// Consumes the request and returns the raw module being relocated.
    #[inline]
    pub fn into_raw(self) -> RawDylib<D> {
        self.raw
    }
}

enum RelocationScope<D> {
    Owned(Box<[LoadedCore<D>]>),
    Shared(Arc<[LoadedCore<D>]>),
}

/// Per-module relocation inputs produced by the caller's runtime policy.
pub struct RelocationInputs<D> {
    scope: RelocationScope<D>,
    binding: BindingMode,
}

impl<D> RelocationInputs<D> {
    #[inline]
    pub fn new(scope: impl IntoIterator<Item = LoadedCore<D>>) -> Self {
        Self {
            scope: RelocationScope::Owned(scope.into_iter().collect()),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn shared(scope: Arc<[LoadedCore<D>]>) -> Self {
        Self {
            scope: RelocationScope::Shared(scope),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D>] {
        match &self.scope {
            RelocationScope::Owned(scope) => scope,
            RelocationScope::Shared(scope) => scope,
        }
    }

    #[inline]
    pub fn binding(&self) -> BindingMode {
        self.binding
    }

    #[inline]
    pub fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    #[inline]
    pub fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }

    #[inline]
    pub fn with_binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }
}

/// Runtime policy for assembling relocation inputs.
pub trait RelocationPlanner<K, D: 'static> {
    /// Plans the relocation scope and binding mode for one module.
    fn plan(&mut self, req: &RelocationRequest<'_, K, D>) -> Result<RelocationInputs<D>>;
}

/// Default relocation planner that uses the request's batch-start scope and
/// the ELF object's default binding mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRelocationPlanner;

impl<K, D: 'static> RelocationPlanner<K, D> for DefaultRelocationPlanner {
    #[inline]
    fn plan(&mut self, req: &RelocationRequest<'_, K, D>) -> Result<RelocationInputs<D>> {
        Ok(RelocationInputs::shared(req.shared_scope().clone()))
    }
}

impl<K, D: 'static, F> RelocationPlanner<K, D> for F
where
    F: for<'a> FnMut(&RelocationRequest<'a, K, D>) -> Result<RelocationInputs<D>>,
{
    #[inline]
    fn plan(&mut self, req: &RelocationRequest<'_, K, D>) -> Result<RelocationInputs<D>> {
        self(req)
    }
}
