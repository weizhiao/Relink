use crate::{
    Error, LinkerError, Result, UnresolvedDependency,
    image::{ModuleSearch, PathTokens},
};
use alloc::boxed::Box;

pub(crate) type LoaderVisitor<'visit> =
    dyn for<'search> FnMut(&'search ModuleSearch) -> Result<bool> + 'visit;
pub(super) type LoaderProvider<'a> =
    dyn for<'visit> Fn(&mut LoaderVisitor<'visit>) -> Result<()> + 'a;

/// The input being resolved by a [`ResolveRequest`].
pub enum ResolveInput<'a, Root> {
    /// A root supplied directly to a linker load operation.
    Root {
        /// Resolver-specific root input supplied by the caller.
        root: Root,
    },
    /// One `DT_NEEDED` edge of an requesting module.
    Dependency {
        /// Library name stored in the owner's `DT_NEEDED` entry.
        needed: &'a [u8],
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
        needed: &'a [u8],
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

    /// Transforms an owned root while preserving dependency and search context.
    ///
    /// Resolver adapters can consume resources carried by their root input and
    /// forward the remaining path to another resolver. The closure is not
    /// called for dependency requests.
    pub fn map_root<T>(self, map: impl FnOnce(Root) -> T) -> ResolveRequest<'a, T> {
        let input = match self.input {
            ResolveInput::Root { root } => ResolveInput::Root { root: map(root) },
            ResolveInput::Dependency { needed } => ResolveInput::Dependency { needed },
        };
        ResolveRequest {
            input,
            search: self.search,
            tokens: self.tokens,
            loaders: self.loaders,
        }
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
