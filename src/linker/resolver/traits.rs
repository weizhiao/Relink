use super::ResolveRequest;
use crate::{
    Result, arch::NativeArch, image::ModuleHandle, input::ElfReader, relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

/// A key-resolution result chosen by caller policy.
pub enum ResolvedKey<'cfg, K, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    /// Reuses a module that is already visible in the current link context.
    Existing(K),
    /// Loads a new module for the provided canonical key and target arch.
    Load {
        /// Canonical key that should identify the loaded module.
        key: K,
        /// Reader used to load the resolved ELF image.
        reader: Box<dyn ElfReader + 'cfg>,
    },
    /// Provides a module not yet committed to the current context and its dependencies.
    ///
    /// The underlying allocation may already be shared elsewhere. The module is
    /// published and initialized with this transaction. Use [`Self::Existing`]
    /// only for a key already committed to the current context.
    Module {
        /// Canonical key that should identify the module.
        key: K,
        /// Module exposed for symbol lookup.
        module: ModuleHandle<Arch, Tls>,
        /// Dependencies resolved as part of this graph fragment.
        deps: Vec<ResolvedKey<'cfg, K, Arch, Tls>>,
    },
}

impl<'cfg, K, Arch: RelocationArch, Tls: TlsResolver<Arch>> ResolvedKey<'cfg, K, Arch, Tls> {
    /// Creates a result that reuses an already committed visible key.
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    /// Creates a result that loads a new module from the provided reader.
    #[inline]
    pub fn load(key: K, reader: impl ElfReader + 'cfg) -> Self {
        Self::Load {
            key,
            reader: Box::new(reader),
        }
    }

    /// Creates a result backed by a module not yet committed to this context.
    #[inline]
    pub fn module(
        key: K,
        module: impl Into<ModuleHandle<Arch, Tls>>,
        deps: impl Into<Vec<ResolvedKey<'cfg, K, Arch, Tls>>>,
    ) -> Self {
        Self::Module {
            key,
            module: module.into(),
            deps: deps.into(),
        }
    }
}

/// Key-resolution policy used by [`super::super::Linker`].
pub trait KeyResolver<K, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    /// Per-load root input owned by this resolver invocation.
    ///
    /// It may carry non-cloneable resources such as an already-open file.
    type Request;

    /// Maps a root request to the key used for an existing-module lookup.
    fn map_request(&self, request: &Self::Request) -> K;

    /// Maps an ELF module name such as `DT_SONAME` or `DT_NEEDED` to a key.
    ///
    /// Returning `None` disables linker-managed name aliases. Dependency
    /// requests are still passed to [`resolve`](Self::resolve).
    #[inline]
    fn map_name(&self, _name: &str) -> Option<K> {
        None
    }

    /// Resolves a root input or one `DT_NEEDED` dependency.
    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, Self::Request, K>,
    ) -> Result<ResolvedKey<'cfg, K, Arch, Tls>>
    where
        K: 'cfg;
}
