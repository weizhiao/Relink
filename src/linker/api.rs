use crate::{
    Result,
    image::{LoadedCore, RawDylib},
};

use super::request::{DependencyRequest, RelocationRequest};

/// A module chosen by a loader or dependency resolver.
pub enum ResolvedModule<K, D: 'static> {
    /// Reuses a module that is already present in the current context.
    ///
    /// Resolvers can return this after consulting [`DependencyRequest::context`]
    /// when they want cache-first behavior.
    Existing(K),
    /// Introduces a newly mapped but not yet relocated shared object.
    Raw(K, RawDylib<D>),
    /// Introduces a dependency that is already relocated and ready to use.
    Loaded(K, LoadedCore<D>),
}

impl<K, D> ResolvedModule<K, D> {
    /// Creates a raw module result.
    #[inline]
    pub fn new_raw(key: K, dylib: RawDylib<D>) -> Self {
        Self::Raw(key, dylib)
    }

    /// Creates an already-loaded module result.
    #[inline]
    pub fn new_loaded(key: K, dylib: LoadedCore<D>) -> Self {
        Self::Loaded(key, dylib)
    }

    /// Reuses an existing key from the current context.
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    /// Returns the selected key.
    #[inline]
    pub fn key(&self) -> &K {
        match self {
            Self::Existing(key) | Self::Raw(key, _) | Self::Loaded(key, _) => key,
        }
    }
}

/// Resolver callbacks for root modules and `DT_NEEDED` edges.
///
/// A resolver turns a caller-defined key into a concrete root module, and can
/// also resolve dependency requests produced while linking that root.
///
/// The root-loading and dependency-resolution steps are kept together because
/// they usually share the same cache lookup, canonicalization, and probing
/// logic.
///
/// A root load turns a caller-defined key into a concrete module selected for the
/// current [`LinkContext`]. It may canonicalize the key by returning a
/// different [`ResolvedModule::key()`] than the requested one.
pub trait ModuleResolver<K, D: 'static> {
    /// Loads one module entry point identified by `key`.
    fn load(&mut self, key: &K) -> Result<ResolvedModule<K, D>>;
    fn resolve(
        &mut self,
        req: &DependencyRequest<'_, K, D>,
    ) -> Result<Option<ResolvedModule<K, D>>>;
}

/// Relocation callbacks for newly mapped modules discovered during `load()`.
///
/// A relocator receives each raw module after dependency resolution has fixed
/// its direct dependency set and established the currently visible load scope.
///
/// For ad-hoc use, any closure `FnMut(RelocationRequest) -> Result<LoadedCore>`
/// also implements this trait.
pub trait ModuleRelocator<K, D: 'static> {
    /// Relocates one newly mapped module into its ready-to-use loaded form.
    fn relocate(&mut self, req: RelocationRequest<'_, K, D>) -> Result<LoadedCore<D>>;
}

impl<K, D: 'static, F> ModuleRelocator<K, D> for F
where
    F: for<'a> FnMut(RelocationRequest<'a, K, D>) -> Result<LoadedCore<D>>,
{
    #[inline]
    fn relocate(&mut self, req: RelocationRequest<'_, K, D>) -> Result<LoadedCore<D>> {
        (self)(req)
    }
}
