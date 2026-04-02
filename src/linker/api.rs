use super::request::{DependencyRequest, RelocationRequest};
use crate::{Result, image::LoadedCore, input::ElfReader, relocation::BindingMode};
use alloc::boxed::Box;

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

/// Runtime key-resolution policy used by [`super::LinkContext`].
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
    /// Plans the current relocation scope and binding mode for one module.
    fn plan(&mut self, req: &RelocationRequest<'_, K, D>) -> Result<RelocationInputs<D>>;
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
