use crate::{
    LinkerError, Result, UnresolvedDependencyError,
    arch::ArchKind,
    image::{LoadedCore, RawDylib, RawDynamic, ScannedDynamic},
    relocation::{BindingMode, RelocationArch},
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

impl<D: 'static, Arch: RelocationArch> DependencyOwner for RawDylib<D, Arch> {
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

impl<D: 'static, Arch: RelocationArch> DependencyOwner for RawDynamic<D, Arch> {
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

impl<Arch: RelocationArch> DependencyOwner for ScannedDynamic<Arch> {
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

/// A root module resolution request.
pub struct RootRequest<'a, K: Clone> {
    key: &'a K,
    is_visible: &'a dyn Fn(&K) -> bool,
}

impl<'a, K: Clone> RootRequest<'a, K> {
    #[inline]
    pub(crate) fn new(key: &'a K, is_visible: &'a dyn Fn(&K) -> bool) -> Self {
        Self { key, is_visible }
    }

    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    #[inline]
    pub fn is_visible(&self, key: &K) -> bool {
        (self.is_visible)(key)
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K: Clone> {
    owner_key: &'a K,
    owner: &'a dyn DependencyOwner,
    needed_index: usize,
    is_visible: &'a dyn Fn(&K) -> bool,
}

impl<'a, K: Clone> DependencyRequest<'a, K> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        owner: &'a dyn DependencyOwner,
        needed_index: usize,
        is_visible: &'a dyn Fn(&K) -> bool,
    ) -> Self {
        Self {
            owner_key,
            owner,
            needed_index,
            is_visible,
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
    pub fn is_visible(&self, key: &K) -> bool {
        (self.is_visible)(key)
    }

    #[inline]
    pub fn unresolved(&self) -> crate::Error {
        LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
            self.owner_name(),
            self.needed(),
        )))
        .into()
    }
}

/// Read-only modules that should be visible to a link operation without being
/// committed into its local [`LinkContext`](super::LinkContext).
pub trait VisibleModules<K: Clone, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    fn contains_key(&self, _key: &K) -> bool {
        false
    }

    fn direct_deps(&self, _key: &K) -> Option<Box<[K]>> {
        None
    }

    fn loaded(&self, _key: &K) -> Option<LoadedCore<D, Arch>> {
        None
    }
}

impl<K: Clone, D: 'static, Arch: RelocationArch> VisibleModules<K, D, Arch> for () {}

impl<K: Clone, D: 'static, Arch, V> VisibleModules<K, D, Arch> for &V
where
    Arch: RelocationArch,
    V: VisibleModules<K, D, Arch> + ?Sized,
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
    fn loaded(&self, key: &K) -> Option<LoadedCore<D, Arch>> {
        (**self).loaded(key)
    }
}

/// A mapped but unrelocated dynamic image observed during a link operation.
pub struct StagedDynamic<'a, K, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    key: &'a K,
    raw: &'a RawDynamic<D, Arch>,
}

impl<'a, K, D: 'static, Arch> StagedDynamic<'a, K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(key: &'a K, raw: &'a RawDynamic<D, Arch>) -> Self {
        Self { key, raw }
    }

    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    #[inline]
    pub fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.raw.mapped_len()
    }

    #[inline]
    pub fn raw(&self) -> &'a RawDynamic<D, Arch> {
        self.raw
    }
}

/// Observer for modules staged by [`super::Linker`].
pub trait LoadObserver<K, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    fn on_staged_dynamic(&mut self, _event: StagedDynamic<'_, K, D, Arch>) -> Result<()> {
        Ok(())
    }
}

impl<K, D: 'static, Arch: RelocationArch> LoadObserver<K, D, Arch> for () {}

impl<K, D: 'static, Arch, F> LoadObserver<K, D, Arch> for F
where
    Arch: RelocationArch,
    F: for<'a> FnMut(StagedDynamic<'a, K, D, Arch>) -> Result<()>,
{
    #[inline]
    fn on_staged_dynamic(&mut self, event: StagedDynamic<'_, K, D, Arch>) -> Result<()> {
        self(event)
    }
}

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<'a, K, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    key: &'a K,
    raw: RawDynamic<D, Arch>,
    scope: &'a Arc<[LoadedCore<D, Arch>]>,
}

impl<'a, K, D: 'static, Arch> RelocationRequest<'a, K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        raw: RawDynamic<D, Arch>,
        scope: &'a Arc<[LoadedCore<D, Arch>]>,
    ) -> Self {
        Self { key, raw, scope }
    }

    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    #[inline]
    pub fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D, Arch>] {
        self.scope
    }

    #[inline]
    pub fn shared_scope(&self) -> &Arc<[LoadedCore<D, Arch>]> {
        self.scope
    }

    #[inline]
    pub fn raw(&self) -> &RawDynamic<D, Arch> {
        &self.raw
    }

    #[inline]
    pub(crate) fn into_raw(self) -> RawDynamic<D, Arch> {
        self.raw
    }
}

enum RelocationScope<D: 'static, Arch: RelocationArch> {
    Owned(Box<[LoadedCore<D, Arch>]>),
    Shared(Arc<[LoadedCore<D, Arch>]>),
}

/// Per-module relocation inputs produced by the caller's runtime policy.
pub struct RelocationInputs<D: 'static = (), Arch: RelocationArch = crate::arch::NativeArch> {
    scope: RelocationScope<D, Arch>,
    binding: BindingMode,
}

impl<D: 'static, Arch> RelocationInputs<D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub fn new<I, R>(scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<LoadedCore<D, Arch>>,
    {
        Self {
            scope: RelocationScope::Owned(scope.into_iter().map(Into::into).collect()),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn shared(scope: Arc<[LoadedCore<D, Arch>]>) -> Self {
        Self {
            scope: RelocationScope::Shared(scope),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn scope(&self) -> &[LoadedCore<D, Arch>] {
        match &self.scope {
            RelocationScope::Owned(scope) => scope,
            RelocationScope::Shared(scope) => scope,
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (Arc<[LoadedCore<D, Arch>]>, BindingMode) {
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
pub trait RelocationPlanner<K, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, K, D, Arch>,
    ) -> Result<RelocationInputs<D, Arch>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRelocationPlanner;

impl<K, D: 'static, Arch> RelocationPlanner<K, D, Arch> for DefaultRelocationPlanner
where
    Arch: RelocationArch,
{
    #[inline]
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, K, D, Arch>,
    ) -> Result<RelocationInputs<D, Arch>> {
        Ok(RelocationInputs::shared(req.shared_scope().clone()))
    }
}

impl<K, D: 'static, Arch, F> RelocationPlanner<K, D, Arch> for F
where
    Arch: RelocationArch,
    F: for<'a> FnMut(&RelocationRequest<'a, K, D, Arch>) -> Result<RelocationInputs<D, Arch>>,
{
    #[inline]
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, K, D, Arch>,
    ) -> Result<RelocationInputs<D, Arch>> {
        self(req)
    }
}
