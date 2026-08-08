use crate::{
    Error, LinkerError, Result, UnresolvedDependency,
    image::{Module, ModuleSearch, RawDynamic, ScannedDynamic},
    memory::RegionAccess,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::boxed::Box;

pub(crate) type LoaderVisitor<'visit> =
    dyn for<'search> FnMut(&'search ModuleSearch) -> Result<bool> + 'visit;
pub(super) type LoaderProvider<'a> =
    dyn for<'visit> Fn(&mut LoaderVisitor<'visit>) -> Result<()> + 'a;

pub(crate) trait DependencySource {
    fn search(&self) -> &ModuleSearch;
    fn needed_len(&self) -> usize;
    fn needed(&self, index: usize) -> Option<&str>;
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    DependencySource for RawDynamic<D, Arch, R, Tls>
{
    #[inline]
    fn search(&self) -> &ModuleSearch {
        self.core_ref()
            .search()
            .expect("ELF cores always retain filesystem search metadata")
    }

    #[inline]
    fn needed_len(&self) -> usize {
        self.core_ref().needed_libs().len()
    }

    #[inline]
    fn needed(&self, index: usize) -> Option<&str> {
        self.core_ref().needed_libs().get(index).copied()
    }
}

impl<Arch: RelocationArch> DependencySource for ScannedDynamic<Arch> {
    #[inline]
    fn search(&self) -> &ModuleSearch {
        ScannedDynamic::search(self)
    }

    #[inline]
    fn needed_len(&self) -> usize {
        self.needed_libs().len()
    }

    #[inline]
    fn needed(&self, index: usize) -> Option<&str> {
        self.needed_lib(index)
    }
}

/// A root module resolution request.
pub struct RootRequest<'a, K: Clone, Q: ?Sized = K> {
    key: &'a K,
    search: Option<&'a ModuleSearch>,
    contains_key: &'a dyn Fn(&Q) -> bool,
}

impl<'a, K: Clone, Q: ?Sized> RootRequest<'a, K, Q> {
    #[inline]
    pub(crate) fn new(
        key: &'a K,
        search: Option<&'a ModuleSearch>,
        contains_key: &'a dyn Fn(&Q) -> bool,
    ) -> Self {
        Self {
            key,
            search,
            contains_key,
        }
    }

    /// Returns the root key requested by the caller.
    #[inline]
    pub fn key(&self) -> &'a K {
        self.key
    }

    /// Returns search metadata for the module that initiated this request.
    #[inline]
    pub const fn search(&self) -> Option<&'a ModuleSearch> {
        self.search
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
    search: &'a ModuleSearch,
    needed: &'a str,
    loaders: &'a LoaderProvider<'a>,
    contains_key: &'a dyn Fn(&Q) -> bool,
}

impl<'a, K: Clone, Q: ?Sized> DependencyRequest<'a, K, Q> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        search: &'a ModuleSearch,
        needed: &'a str,
        loaders: &'a LoaderProvider<'a>,
        contains_key: &'a dyn Fn(&Q) -> bool,
    ) -> Self {
        Self {
            owner_key,
            search,
            needed,
            loaders,
            contains_key,
        }
    }

    /// Returns the key of the module that owns this dependency edge.
    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns search metadata for the module that owns this dependency edge.
    #[inline]
    pub const fn search(&self) -> &'a ModuleSearch {
        self.search
    }

    /// Returns the `DT_NEEDED` entry being resolved.
    #[inline]
    pub fn needed(&self) -> &'a str {
        self.needed
    }

    /// Visits loaders in direct-to-root order until `visitor` returns `false`.
    #[inline]
    pub fn visit_loaders(
        &self,
        mut visitor: impl for<'search> FnMut(&'search ModuleSearch) -> Result<bool>,
    ) -> Result<()> {
        (self.loaders)(&mut visitor)
    }

    /// Returns whether `key` names a module reusable by this request.
    #[inline]
    pub fn contains_key(&self, key: &Q) -> bool {
        (self.contains_key)(key)
    }

    /// Creates the standard unresolved-dependency error for this edge.
    #[inline]
    pub fn unresolved(&self) -> Error {
        LinkerError::UnresolvedDependency(Box::new(UnresolvedDependency::new(
            self.search.name(),
            self.needed(),
        )))
        .into()
    }
}
