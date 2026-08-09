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
pub struct RootRequest<'a, Request, K> {
    request: &'a Request,
    key: Option<K>,
    search: Option<&'a ModuleSearch>,
    contains_key: &'a dyn Fn(&K) -> bool,
}

impl<'a, Request, K> RootRequest<'a, Request, K> {
    #[inline]
    pub(crate) fn new(
        request: &'a Request,
        key: Option<K>,
        search: Option<&'a ModuleSearch>,
        contains_key: &'a dyn Fn(&K) -> bool,
    ) -> Self {
        Self {
            request,
            key,
            search,
            contains_key,
        }
    }

    /// Returns the root request supplied by the caller.
    #[inline]
    pub fn request(&self) -> &'a Request {
        self.request
    }

    /// Returns the precomputed lookup key for this request, when available.
    #[inline]
    pub fn key(&self) -> Option<&K> {
        self.key.as_ref()
    }

    /// Returns search metadata for the module that initiated this request.
    #[inline]
    pub const fn search(&self) -> Option<&'a ModuleSearch> {
        self.search
    }

    /// Returns whether `key` names a module reusable by this request.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        (self.contains_key)(key)
    }
}

/// A single dependency-resolution request.
pub struct DependencyRequest<'a, K> {
    owner_key: &'a K,
    search: &'a ModuleSearch,
    needed: &'a str,
    loaders: &'a LoaderProvider<'a>,
    contains_key: &'a dyn Fn(&K) -> bool,
}

impl<'a, K> DependencyRequest<'a, K> {
    #[inline]
    pub(crate) fn new(
        owner_key: &'a K,
        search: &'a ModuleSearch,
        needed: &'a str,
        loaders: &'a LoaderProvider<'a>,
        contains_key: &'a dyn Fn(&K) -> bool,
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
    pub fn contains_key(&self, key: &K) -> bool {
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
