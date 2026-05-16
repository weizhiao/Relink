use crate::{
    LinkerError, Result, UnresolvedDependency,
    arch::ArchKind,
    image::{ModuleHandle, ModuleScope, RawDylib, RawDynamic, ScannedDynamic},
    input::Path,
    relocation::{BindingMode, RelocationArch},
};
use alloc::boxed::Box;

/// Common metadata needed while resolving one dependency edge.
pub trait DependencyOwner {
    fn path(&self) -> &Path;
    fn name(&self) -> &str;
    fn rpath(&self) -> Option<&str>;
    fn runpath(&self) -> Option<&str>;
    fn interp(&self) -> Option<&str>;
    fn needed_len(&self) -> usize;
    fn needed_lib(&self, index: usize) -> Option<&str>;
}

impl<D: 'static, Arch: RelocationArch> DependencyOwner for RawDylib<D, Arch> {
    #[inline]
    fn path(&self) -> &Path {
        self.path()
    }

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
    fn path(&self) -> &Path {
        self.path()
    }

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
    fn path(&self) -> &Path {
        self.path()
    }

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
    pub fn owner_path(&self) -> &'a Path {
        self.owner.path()
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
        LinkerError::UnresolvedDependency(Box::new(UnresolvedDependency::new(
            self.owner_name(),
            self.needed(),
        )))
        .into()
    }
}

/// Read-only modules that should be visible to a link operation without being
/// committed into its local [`LinkContext`](super::LinkContext).
pub trait VisibleModules<K: Clone, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    fn contains_key(&self, key: &K) -> bool {
        self.module(key).is_some()
    }

    fn direct_deps(&self, _key: &K) -> Option<Box<[K]>> {
        None
    }

    fn module(&self, _key: &K) -> Option<ModuleHandle<Arch>> {
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
    fn module(&self, key: &K) -> Option<ModuleHandle<Arch>> {
        (**self).module(key)
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
    scope: &'a ModuleScope<Arch>,
    _marker: core::marker::PhantomData<fn() -> D>,
}

impl<'a, K, D: 'static, Arch> RelocationRequest<'a, K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(key: &'a K, raw: RawDynamic<D, Arch>, scope: &'a ModuleScope<Arch>) -> Self {
        Self {
            key,
            raw,
            scope,
            _marker: core::marker::PhantomData,
        }
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
    pub fn scope(&self) -> &ModuleScope<Arch> {
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

/// Per-module relocation inputs produced by the caller's runtime policy.
pub struct RelocationInputs<D: 'static = (), Arch: RelocationArch = crate::arch::NativeArch> {
    scope: ModuleScope<Arch>,
    _marker: core::marker::PhantomData<fn() -> D>,
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
        R: Into<ModuleHandle<Arch>>,
    {
        Self {
            scope: ModuleScope::new(scope),
            _marker: core::marker::PhantomData,
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub fn scope(scope: ModuleScope<Arch>) -> Self {
        Self {
            scope,
            _marker: core::marker::PhantomData,
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ModuleScope<Arch>, BindingMode) {
        (self.scope, self.binding)
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

    pub fn extend_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        self.scope = self.scope.extend(scope);
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
        Ok(RelocationInputs::scope(req.scope().clone()))
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
