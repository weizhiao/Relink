use super::{runtime::AnyRawDynamic, view::DependencyGraphView};
use crate::{
    Result,
    arch::ArchKind,
    image::{AnyScannedDynamic, LoadedModule, RawDylib, RawDynamic},
    relocation::{BindingMode, RelocationArch},
    sync::Arc,
};
use alloc::boxed::Box;

/// Common metadata needed while resolving one dependency edge.
pub trait DependencyOwner {
    fn name(&self) -> &str;
    fn arch_kind(&self) -> ArchKind;
    fn rpath(&self) -> Option<&str>;
    fn runpath(&self) -> Option<&str>;
    fn interp(&self) -> Option<&str>;
    fn needed_len(&self) -> usize;
    fn needed_lib(&self, index: usize) -> Option<&str>;
}

impl<D: 'static, Arch: RelocationArch> DependencyOwner for RawDylib<D, Arch> {
    #[inline]
    fn name(&self) -> &str {
        self.name()
    }

    #[inline]
    fn arch_kind(&self) -> ArchKind {
        Arch::KIND
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

impl<D: 'static, Arch: RelocationArch> DependencyOwner for RawDynamic<D, Arch> {
    #[inline]
    fn name(&self) -> &str {
        self.name()
    }

    #[inline]
    fn arch_kind(&self) -> ArchKind {
        Arch::KIND
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

impl DependencyOwner for AnyScannedDynamic {
    #[inline]
    fn name(&self) -> &str {
        self.name()
    }

    #[inline]
    fn arch_kind(&self) -> ArchKind {
        self.arch_kind()
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
        self.needed_len()
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

    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    #[inline]
    pub fn owner(&self) -> &'a dyn DependencyOwner {
        self.owner
    }

    #[inline]
    pub fn owner_name(&self) -> &'a str {
        self.owner.name()
    }

    #[inline]
    pub fn owner_arch(&self) -> ArchKind {
        self.owner.arch_kind()
    }

    #[inline]
    pub fn needed(&self) -> &'a str {
        self.owner
            .needed_lib(self.needed_index)
            .expect("DT_NEEDED index out of bounds")
    }

    #[inline]
    pub fn needed_index(&self) -> usize {
        self.needed_index
    }

    #[inline]
    pub fn rpath(&self) -> Option<&'a str> {
        self.owner.rpath()
    }

    #[inline]
    pub fn runpath(&self) -> Option<&'a str> {
        self.owner.runpath()
    }

    #[inline]
    pub fn interp(&self) -> Option<&'a str> {
        self.owner.interp()
    }

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
pub trait VisibleModules<K: Clone, D: 'static> {
    fn contains_key(&self, _key: &K) -> bool {
        false
    }

    fn direct_deps(&self, _key: &K) -> Option<Box<[K]>> {
        None
    }

    fn loaded(&self, _key: &K) -> Option<LoadedModule<D>> {
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
    fn loaded(&self, key: &K) -> Option<LoadedModule<D>> {
        (**self).loaded(key)
    }
}

/// A mapped but unrelocated dynamic image observed during a link operation.
pub struct StagedDynamic<'a, K, D: 'static> {
    key: &'a K,
    raw: &'a AnyRawDynamic<D>,
}

impl<'a, K, D: 'static> StagedDynamic<'a, K, D> {
    #[inline]
    pub(crate) fn new(key: &'a K, raw: &'a AnyRawDynamic<D>) -> Self {
        Self { key, raw }
    }

    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    #[inline]
    pub fn arch_kind(&self) -> ArchKind {
        self.raw.arch_kind()
    }

    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.raw.mapped_len()
    }
}

/// Observer for modules staged by [`super::Linker`].
pub trait LoadObserver<K, D: 'static> {
    fn on_staged_dynamic(&mut self, _event: StagedDynamic<'_, K, D>) -> Result<()> {
        Ok(())
    }
}

impl<K, D: 'static> LoadObserver<K, D> for () {}

impl<K, D: 'static, F> LoadObserver<K, D> for F
where
    F: for<'a> FnMut(StagedDynamic<'a, K, D>) -> Result<()>,
{
    #[inline]
    fn on_staged_dynamic(&mut self, event: StagedDynamic<'_, K, D>) -> Result<()> {
        self(event)
    }
}

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<'a, K, D: 'static> {
    key: &'a K,
    raw: AnyRawDynamic<D>,
    scope: &'a Arc<[LoadedModule<D>]>,
}

impl<'a, K, D: 'static> RelocationRequest<'a, K, D> {
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        raw: AnyRawDynamic<D>,
        scope: &'a Arc<[LoadedModule<D>]>,
    ) -> Self {
        Self { key, raw, scope }
    }

    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    #[inline]
    pub fn arch_kind(&self) -> ArchKind {
        self.raw.arch_kind()
    }

    #[inline]
    pub fn scope(&self) -> &[LoadedModule<D>] {
        self.scope
    }

    #[inline]
    pub fn shared_scope(&self) -> &Arc<[LoadedModule<D>]> {
        self.scope
    }

    #[inline]
    pub(crate) fn into_raw(self) -> AnyRawDynamic<D> {
        self.raw
    }
}

enum RelocationScope<D: 'static> {
    Owned(Box<[LoadedModule<D>]>),
    Shared(Arc<[LoadedModule<D>]>),
}

/// Per-module relocation inputs produced by the caller's runtime policy.
pub struct RelocationInputs<D: 'static = ()> {
    scope: RelocationScope<D>,
    binding: BindingMode,
}

impl<D: 'static> RelocationInputs<D> {
    #[inline]
    pub fn new<I, R>(scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<LoadedModule<D>>,
    {
        Self {
            scope: RelocationScope::Owned(scope.into_iter().map(Into::into).collect()),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn shared(scope: Arc<[LoadedModule<D>]>) -> Self {
        Self {
            scope: RelocationScope::Shared(scope),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn scope(&self) -> &[LoadedModule<D>] {
        match &self.scope {
            RelocationScope::Owned(scope) => scope,
            RelocationScope::Shared(scope) => scope,
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (Arc<[LoadedModule<D>]>, BindingMode) {
        let scope = match self.scope {
            RelocationScope::Owned(scope) => Arc::from(scope),
            RelocationScope::Shared(scope) => scope,
        };
        (scope, self.binding)
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
    fn plan(&mut self, req: &RelocationRequest<'_, K, D>) -> Result<RelocationInputs<D>>;
}

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
