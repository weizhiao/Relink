use crate::{
    Error, LinkResolverError, LinkerError, Result, UnresolvedDependency,
    image::{Module, ModuleSearch, PathTokens, RawDynamic, ScannedDynamic},
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

/// The input being resolved by a [`ResolveRequest`].
pub enum ResolveInput<'a, Request, K> {
    /// A root supplied directly to a linker load operation.
    Root { request: Request, key: K },
    /// One `DT_NEEDED` edge of an already scanned module.
    Dependency { needed: &'a str },
}

/// A root or dependency resolution request.
pub struct ResolveRequest<'a, Request, K> {
    input: ResolveInput<'a, Request, K>,
    search: &'a ModuleSearch,
    tokens: &'a PathTokens,
    loaders: &'a LoaderProvider<'a>,
    contains_key: &'a dyn Fn(&K) -> bool,
}

impl<'a, Request, K> ResolveRequest<'a, Request, K> {
    #[inline]
    pub(crate) const fn root(
        request: Request,
        key: K,
        search: &'a ModuleSearch,
        tokens: &'a PathTokens,
        loaders: &'a LoaderProvider<'a>,
        contains_key: &'a dyn Fn(&K) -> bool,
    ) -> Self {
        Self {
            input: ResolveInput::Root { request, key },
            search,
            tokens,
            loaders,
            contains_key,
        }
    }

    #[inline]
    pub(crate) const fn dependency(
        needed: &'a str,
        search: &'a ModuleSearch,
        tokens: &'a PathTokens,
        loaders: &'a LoaderProvider<'a>,
        contains_key: &'a dyn Fn(&K) -> bool,
    ) -> Self {
        Self {
            input: ResolveInput::Dependency { needed },
            search,
            tokens,
            loaders,
            contains_key,
        }
    }

    /// Returns the kind-specific input being resolved.
    #[inline]
    pub const fn input(&self) -> &ResolveInput<'a, Request, K> {
        &self.input
    }

    /// Returns mutable access to the kind-specific input.
    #[inline]
    pub fn input_mut(&mut self) -> &mut ResolveInput<'a, Request, K> {
        &mut self.input
    }

    /// Returns search metadata for the request owner.
    #[inline]
    pub const fn search(&self) -> &'a ModuleSearch {
        self.search
    }

    #[inline]
    pub(crate) const fn tokens(&self) -> &'a PathTokens {
        self.tokens
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

    /// Creates the standard not-found error for this request.
    pub fn unresolved(&self) -> Error {
        match self.input() {
            ResolveInput::Root { .. } => {
                LinkerError::resolver(LinkResolverError::RootNotFound).into()
            }
            ResolveInput::Dependency { needed } => LinkerError::UnresolvedDependency(Box::new(
                UnresolvedDependency::new(self.search.name(), needed),
            ))
            .into(),
        }
    }
}
