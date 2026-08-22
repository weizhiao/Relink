use super::{super::ModuleKey, ResolveRequest};
use crate::{
    Result, arch::NativeArch, image::ModuleHandle, input::ElfReader, relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

/// A key-resolution result chosen by caller policy.
pub enum ResolvedKey<'cfg, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    /// Reuses a module that is already visible in the current link context.
    Existing(ModuleKey),
    /// Provides a load candidate for the canonical key and target arch.
    ///
    /// The linker reuses a visible module with the same key before loading the
    /// reader.
    Load {
        /// Canonical key that should identify the loaded module.
        key: ModuleKey,
        /// Reader used to load the resolved ELF image.
        reader: Box<dyn ElfReader + 'cfg>,
    },
    /// Provides a module candidate and its dependencies.
    ///
    /// The underlying allocation may already be shared elsewhere. A visible
    /// module with the same key is reused; otherwise this module is published
    /// and initialized with the transaction.
    Module {
        /// Canonical key that should identify the module.
        key: ModuleKey,
        /// Module exposed for symbol lookup.
        module: ModuleHandle<Arch, Tls>,
        /// Dependencies resolved as part of this graph fragment.
        deps: Vec<ResolvedKey<'cfg, Arch, Tls>>,
    },
}

impl<'cfg, Arch: RelocationArch, Tls: TlsResolver<Arch>> ResolvedKey<'cfg, Arch, Tls> {
    /// Creates a result that reuses an already committed visible key.
    #[inline]
    pub fn existing(key: impl Into<ModuleKey>) -> Self {
        Self::Existing(key.into())
    }

    /// Creates a result that loads a new module from the provided reader.
    #[inline]
    pub fn load(key: impl Into<ModuleKey>, reader: impl ElfReader + 'cfg) -> Self {
        Self::Load {
            key: key.into(),
            reader: Box::new(reader),
        }
    }

    /// Creates a result backed by a module not yet committed to this context.
    #[inline]
    pub fn module(
        key: impl Into<ModuleKey>,
        module: impl Into<ModuleHandle<Arch, Tls>>,
        deps: impl Into<Vec<ResolvedKey<'cfg, Arch, Tls>>>,
    ) -> Self {
        Self::Module {
            key: key.into(),
            module: module.into(),
            deps: deps.into(),
        }
    }
}

/// Key-resolution policy used by [`super::super::Linker`].
pub trait KeyResolver<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    /// Root input owned by one linker load operation.
    ///
    /// It may carry non-cloneable resources such as an already-open file.
    type Root;

    /// Maps a root input to the key used for an existing-module lookup.
    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str;

    /// Resolves a root input or one `DT_NEEDED` dependency.
    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, Self::Root>,
    ) -> Result<ResolvedKey<'cfg, Arch, Tls>>;
}
