use super::view::DependencyGraphView;
use crate::{
    Result,
    image::{LoadedCore, RawDylib, ScannedDylib},
    relocation::BindingMode,
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

impl<D: 'static> DependencyOwner for ScannedDylib<D> {
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
pub struct DependencyRequest<'a, K, D: 'static> {
    owner_key: &'a K,
    owner: &'a dyn DependencyOwner,
    needed_index: usize,
    visible: DependencyGraphView<'a, K, D>,
}

impl<'a, K, D: 'static> DependencyRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        owner: &'a dyn DependencyOwner,
        needed_index: usize,
        visible: DependencyGraphView<'a, K, D>,
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

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<'a, K, D: 'static> {
    key: &'a K,
    raw: RawDylib<D>,
    scope: &'a [LoadedCore<D>],
}

impl<'a, K, D: 'static> RelocationRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(key: &'a K, raw: RawDylib<D>, scope: &'a [LoadedCore<D>]) -> Self {
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

    /// Consumes the request and returns the raw module being relocated.
    #[inline]
    pub fn into_raw(self) -> RawDylib<D> {
        self.raw
    }
}

/// Per-module relocation inputs produced by the caller's runtime policy.
pub struct RelocationInputs<D> {
    scope: Box<[LoadedCore<D>]>,
    binding: BindingMode,
}

impl<D> RelocationInputs<D> {
    #[inline]
    pub fn new(scope: impl IntoIterator<Item = LoadedCore<D>>) -> Self {
        Self {
            scope: scope.into_iter().collect(),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D>] {
        &self.scope
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
        Ok(RelocationInputs::new(req.scope().iter().cloned()))
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
