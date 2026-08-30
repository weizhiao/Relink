use crate::{
    Error, LinkerError, Result, UnresolvedDependency,
    image::{Module, ModuleSearch, PathTokens, RawDynamic, ScannedDynamic},
    input::ModuleSourceId,
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
    fn source_id(&self) -> ModuleSourceId;
    fn needed_len(&self) -> usize;
    fn needed(&self, index: usize) -> Option<&str>;
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    DependencySource for RawDynamic<D, Arch, R, Tls>
{
    #[inline]
    fn search(&self) -> &ModuleSearch {
        Module::search(&***self).expect("ELF cores always retain filesystem search metadata")
    }

    #[inline]
    fn source_id(&self) -> ModuleSourceId {
        self.state().instance_id().source_id()
    }

    #[inline]
    fn needed_len(&self) -> usize {
        self.needed_libs().len()
    }

    #[inline]
    fn needed(&self, index: usize) -> Option<&str> {
        self.needed_libs().get(index).copied()
    }
}

impl<Arch: RelocationArch> DependencySource for ScannedDynamic<Arch> {
    #[inline]
    fn search(&self) -> &ModuleSearch {
        ScannedDynamic::search(self)
    }

    #[inline]
    fn source_id(&self) -> ModuleSourceId {
        ScannedDynamic::source_id(self)
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
pub enum ResolveInput<'a, Root> {
    /// A root supplied directly to a linker load operation.
    Root {
        /// Resolver-specific root input supplied by the caller.
        root: Root,
    },
    /// One `DT_NEEDED` edge of an already scanned module.
    Dependency {
        /// Library name stored in the owner's `DT_NEEDED` entry.
        needed: &'a str,
    },
}

/// A root or dependency resolution request.
pub struct ResolveRequest<'a, Root> {
    input: ResolveInput<'a, Root>,
    search: &'a ModuleSearch,
    tokens: &'a PathTokens,
    loaders: &'a LoaderProvider<'a>,
}

impl<'a, Root> ResolveRequest<'a, Root> {
    #[inline]
    pub(crate) const fn root(
        root: Root,
        search: &'a ModuleSearch,
        tokens: &'a PathTokens,
        loaders: &'a LoaderProvider<'a>,
    ) -> Self {
        Self {
            input: ResolveInput::Root { root },
            search,
            tokens,
            loaders,
        }
    }

    #[inline]
    pub(crate) const fn dependency(
        needed: &'a str,
        search: &'a ModuleSearch,
        tokens: &'a PathTokens,
        loaders: &'a LoaderProvider<'a>,
    ) -> Self {
        Self {
            input: ResolveInput::Dependency { needed },
            search,
            tokens,
            loaders,
        }
    }

    /// Returns the kind-specific input being resolved.
    #[inline]
    pub const fn input(&self) -> &ResolveInput<'a, Root> {
        &self.input
    }

    /// Returns search metadata for the request owner.
    #[inline]
    pub const fn search(&self) -> &'a ModuleSearch {
        self.search
    }

    #[inline]
    pub(super) const fn loaders(&self) -> &'a LoaderProvider<'a> {
        self.loaders
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

    /// Creates the standard not-found error for this request.
    pub fn unresolved(&self) -> Error {
        match self.input() {
            ResolveInput::Root { .. } => LinkerError::RootNotFound.into(),
            ResolveInput::Dependency { needed } => LinkerError::UnresolvedDependency(Box::new(
                UnresolvedDependency::new(self.search.name(), needed),
            ))
            .into(),
        }
    }
}
