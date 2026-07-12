use crate::{
    LinkerError, UnresolvedDependency,
    image::{ModuleHandle, RawDynamic, ScannedDynamic},
    input::Path,
    memory::RegionAccess,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::boxed::Box;

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

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> DependencyOwner
    for RawDynamic<D, Arch, R, Tls>
{
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
    contains_key: &'a dyn Fn(&Q) -> bool,
}

impl<'a, K: Clone, Q: ?Sized> RootRequest<'a, K, Q> {
    #[inline]
    pub(crate) fn new(key: &'a K, contains_key: &'a dyn Fn(&Q) -> bool) -> Self {
        Self { key, contains_key }
    }

    /// Returns the root key requested by the caller.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns whether `key` names a module reusable by this request.
    #[inline]
    pub fn contains_key(&self, key: &Q) -> bool {
        (self.contains_key)(key)
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K: Clone, Q: ?Sized = K> {
    owner_key: &'a K,
    owner: &'a dyn DependencyOwner,
    needed_index: usize,
    contains_key: &'a dyn Fn(&Q) -> bool,
}

impl<'a, K: Clone, Q: ?Sized> DependencyRequest<'a, K, Q> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        owner: &'a dyn DependencyOwner,
        needed_index: usize,
        contains_key: &'a dyn Fn(&Q) -> bool,
    ) -> Self {
        Self {
            owner_key,
            owner,
            needed_index,
            contains_key,
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

    /// Returns whether `key` names a module reusable by this request.
    #[inline]
    pub fn contains_key(&self, key: &Q) -> bool {
        (self.contains_key)(key)
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

/// A read-only module visible to a link operation, plus its direct dependency
/// keys.
pub struct VisibleModule<
    K,
    Arch: RelocationArch = crate::arch::NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[K]>,
}

impl<K, Arch, Tls> VisibleModule<K, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates a visible module with the keys of its direct dependencies.
    #[inline]
    pub fn new(module: impl Into<ModuleHandle<Arch, Tls>>, direct_deps: Box<[K]>) -> Self {
        Self {
            module: module.into(),
            direct_deps,
        }
    }

    /// Returns the module handle made visible to the link operation.
    #[inline]
    pub fn module(&self) -> &ModuleHandle<Arch, Tls> {
        &self.module
    }

    /// Returns the direct dependency keys associated with this visible module.
    #[inline]
    pub fn direct_deps(&self) -> &[K] {
        &self.direct_deps
    }

    /// Consumes this value into the module handle and direct dependency keys.
    #[inline]
    pub fn into_parts(self) -> (ModuleHandle<Arch, Tls>, Box<[K]>) {
        (self.module, self.direct_deps)
    }
}

/// Read-only modules that should be visible to a link operation without being
/// committed into its local [`LinkContext`](super::LinkContext).
pub trait VisibleModules<
    K: Clone,
    Arch: RelocationArch = crate::arch::NativeArch,
    Q: ?Sized = K,
    Tls: TlsResolver<Arch> = (),
>
{
    /// Returns whether a module is visible by key.
    fn contains(&self, key: &Q) -> bool {
        self.module(key).is_some()
    }

    /// Returns a retained visible module and its direct dependency keys by key.
    fn module(&self, _key: &Q) -> Option<VisibleModule<K, Arch, Tls>> {
        None
    }
}

impl<K: Clone, Arch: RelocationArch, Q: ?Sized, Tls: TlsResolver<Arch>>
    VisibleModules<K, Arch, Q, Tls> for ()
{
}

impl<K: Clone, Arch, Q, Tls, V> VisibleModules<K, Arch, Q, Tls> for &V
where
    Arch: RelocationArch,
    Q: ?Sized,
    Tls: TlsResolver<Arch>,
    V: VisibleModules<K, Arch, Q, Tls> + ?Sized,
{
    #[inline]
    fn contains(&self, key: &Q) -> bool {
        (**self).contains(key)
    }

    #[inline]
    fn module(&self, key: &Q) -> Option<VisibleModule<K, Arch, Tls>> {
        (**self).module(key)
    }
}
