use crate::{
    LinkerError, Result, UnresolvedDependency,
    arch::ArchKind,
    image::{ModuleHandle, ModuleScope, ModuleScopeBuilder, RawDynamic, ScannedDynamic},
    input::Path,
    memory::{HostRegion, RegionAccess},
    relocation::{BindingMode, RelocationArch},
};
use alloc::{borrow::ToOwned, boxed::Box};

/// Common metadata needed while resolving one dependency edge.
pub trait DependencyOwner {
    /// Returns the owner path/key used by the loader.
    fn path(&self) -> &Path;
    /// Returns the owner name used in diagnostics.
    fn name(&self) -> &str;
    /// Returns the owner's `DT_RPATH`, if present.
    fn rpath(&self) -> Option<&str>;
    /// Returns the owner's `DT_RUNPATH`, if present.
    fn runpath(&self) -> Option<&str>;
    /// Returns the owner's `PT_INTERP` path, if present.
    fn interp(&self) -> Option<&str>;
    /// Returns the number of `DT_NEEDED` entries.
    fn needed_len(&self) -> usize;
    /// Returns one `DT_NEEDED` entry by index.
    fn needed_lib(&self, index: usize) -> Option<&str>;
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> DependencyOwner for RawDynamic<D, Arch, R> {
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
pub struct RootRequest<'a, K: Clone, Q: ?Sized = K> {
    key: &'a K,
    visible_key: &'a dyn Fn(&Q) -> Option<K>,
}

impl<'a, K: Clone, Q: ?Sized> RootRequest<'a, K, Q> {
    #[inline]
    pub(crate) fn new(key: &'a K, visible_key: &'a dyn Fn(&Q) -> Option<K>) -> Self {
        Self { key, visible_key }
    }

    /// Returns the root key requested by the caller.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the actual key to reuse when `key` names a visible module.
    #[inline]
    pub fn visible_key(&self, key: &Q) -> Option<K> {
        (self.visible_key)(key)
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K: Clone, Q: ?Sized = K> {
    owner_key: &'a K,
    owner: &'a dyn DependencyOwner,
    needed_index: usize,
    visible_key: &'a dyn Fn(&Q) -> Option<K>,
}

impl<'a, K: Clone, Q: ?Sized> DependencyRequest<'a, K, Q> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        owner: &'a dyn DependencyOwner,
        needed_index: usize,
        visible_key: &'a dyn Fn(&Q) -> Option<K>,
    ) -> Self {
        Self {
            owner_key,
            owner,
            needed_index,
            visible_key,
        }
    }

    /// Returns the key of the module that owns this dependency edge.
    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns metadata for the owner that requested this dependency.
    #[inline]
    pub fn owner(&self) -> &'a dyn DependencyOwner {
        self.owner
    }

    /// Returns the owner name used in diagnostics.
    #[inline]
    pub fn owner_name(&self) -> &'a str {
        self.owner.name()
    }

    /// Returns the owner path/key used by search-path resolvers.
    #[inline]
    pub fn owner_path(&self) -> &'a Path {
        self.owner.path()
    }

    /// Returns the `DT_NEEDED` entry being resolved.
    #[inline]
    pub fn needed(&self) -> &'a str {
        self.owner
            .needed_lib(self.needed_index)
            .expect("DT_NEEDED index out of bounds")
    }

    /// Returns the index of this dependency in the owner's `DT_NEEDED` list.
    #[inline]
    pub fn needed_index(&self) -> usize {
        self.needed_index
    }

    /// Returns the owner's `DT_RPATH`, if present.
    #[inline]
    pub fn rpath(&self) -> Option<&'a str> {
        self.owner.rpath()
    }

    /// Returns the owner's `DT_RUNPATH`, if present.
    #[inline]
    pub fn runpath(&self) -> Option<&'a str> {
        self.owner.runpath()
    }

    /// Returns the owner's `PT_INTERP` path, if present.
    #[inline]
    pub fn interp(&self) -> Option<&'a str> {
        self.owner.interp()
    }

    /// Returns the actual key to reuse when `key` names a visible module.
    #[inline]
    pub fn visible_key(&self, key: &Q) -> Option<K> {
        (self.visible_key)(key)
    }

    /// Creates the standard unresolved-dependency error for this edge.
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
pub trait VisibleModules<K: Clone, Arch: RelocationArch = crate::arch::NativeArch, Q: ?Sized = K> {
    /// Returns the actual visible key represented by `key`, if any.
    ///
    /// Implementations may use this to canonicalize aliases before the linker
    /// records a dependency edge.
    fn visible_key(&self, key: &Q) -> Option<K>
    where
        Q: ToOwned<Owned = K>,
    {
        self.module(key).is_some().then(|| key.to_owned())
    }

    /// Returns direct dependency keys for a visible module.
    fn direct_deps(&self, _key: &Q) -> Option<Box<[K]>> {
        None
    }

    /// Returns a retained visible module by key.
    fn module(&self, _key: &Q) -> Option<ModuleHandle<Arch>> {
        None
    }
}

impl<K: Clone, Arch: RelocationArch, Q: ?Sized> VisibleModules<K, Arch, Q> for () {}

impl<K: Clone, Arch, Q, V> VisibleModules<K, Arch, Q> for &V
where
    Arch: RelocationArch,
    Q: ?Sized,
    V: VisibleModules<K, Arch, Q> + ?Sized,
{
    #[inline]
    fn visible_key(&self, key: &Q) -> Option<K>
    where
        Q: ToOwned<Owned = K>,
    {
        (**self).visible_key(key)
    }

    #[inline]
    fn direct_deps(&self, key: &Q) -> Option<Box<[K]>> {
        (**self).direct_deps(key)
    }

    #[inline]
    fn module(&self, key: &Q) -> Option<ModuleHandle<Arch>> {
        (**self).module(key)
    }
}

/// A single relocation request for a newly mapped module.
pub struct RelocationRequest<
    'a,
    K,
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    key: &'a K,
    raw: RawDynamic<D, Arch, R>,
    scope: &'a ModuleScope<Arch>,
    _marker: core::marker::PhantomData<fn() -> D>,
}

impl<'a, K, D: 'static, Arch, R> RelocationRequest<'a, K, D, Arch, R>
where
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        raw: RawDynamic<D, Arch, R>,
        scope: &'a ModuleScope<Arch>,
    ) -> Self {
        Self {
            key,
            raw,
            scope,
            _marker: core::marker::PhantomData,
        }
    }

    /// Returns the key of the module being relocated.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the architecture kind of the module being relocated.
    #[inline]
    pub fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    /// Returns the symbol lookup scope that will be retained by the relocated module.
    #[inline]
    pub fn scope(&self) -> &ModuleScope<Arch> {
        self.scope
    }

    /// Returns the mapped dynamic image before relocation.
    #[inline]
    pub fn raw(&self) -> &RawDynamic<D, Arch, R> {
        &self.raw
    }

    #[inline]
    pub(crate) fn into_raw(self) -> RawDynamic<D, Arch, R> {
        self.raw
    }
}

/// Per-module relocation inputs produced by the caller's runtime policy.
pub struct RelocationInputs<Arch: RelocationArch = crate::arch::NativeArch> {
    scope: ModuleScope<Arch>,
    binding: BindingMode,
}

impl<Arch> RelocationInputs<Arch>
where
    Arch: RelocationArch,
{
    /// Creates relocation inputs from an ordered lookup scope.
    #[inline]
    pub fn new<I, R>(scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        let mut modules = ModuleScopeBuilder::new();
        modules.extend(scope);
        Self {
            scope: modules.into_scope(),
            binding: BindingMode::Default,
        }
    }

    /// Creates relocation inputs from an existing module scope.
    #[inline]
    pub fn scope(scope: ModuleScope<Arch>) -> Self {
        Self {
            scope,
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ModuleScope<Arch>, BindingMode) {
        (self.scope, self.binding)
    }

    /// Returns the configured binding mode.
    #[inline]
    pub fn binding(&self) -> BindingMode {
        self.binding
    }

    /// Forces eager binding for this relocation request.
    #[inline]
    pub fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    /// Forces lazy binding for this relocation request.
    #[inline]
    pub fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }

    /// Sets the binding mode for this relocation request.
    #[inline]
    pub fn with_binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }
}

/// Runtime policy for assembling relocation inputs.
pub trait RelocationPlanner<
    K,
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
>
{
    /// Builds relocation inputs for one mapped module.
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, K, D, Arch, R>,
    ) -> Result<RelocationInputs<Arch>>;
}

/// Default relocation planner that uses the request-provided dependency scope.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRelocationPlanner;

impl<K, D: 'static, Arch, R> RelocationPlanner<K, D, Arch, R> for DefaultRelocationPlanner
where
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, K, D, Arch, R>,
    ) -> Result<RelocationInputs<Arch>> {
        Ok(RelocationInputs::scope(req.scope().clone()))
    }
}

impl<K, D: 'static, Arch, R, F> RelocationPlanner<K, D, Arch, R> for F
where
    Arch: RelocationArch,
    R: RegionAccess,
    F: for<'a> FnMut(&RelocationRequest<'a, K, D, Arch, R>) -> Result<RelocationInputs<Arch>>,
{
    #[inline]
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, K, D, Arch, R>,
    ) -> Result<RelocationInputs<Arch>> {
        self(req)
    }
}
