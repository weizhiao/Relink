use crate::{
    Result,
    arch::NativeArch,
    image::ModuleHandle,
    input::ElfReader,
    linker::{DependencyRequest, RootRequest},
    relocation::RelocationArch,
};
use alloc::{boxed::Box, vec::Vec};

/// A key-resolution result chosen by caller policy.
pub enum ResolvedKey<'cfg, K, Arch: RelocationArch = NativeArch> {
    /// Reuses a module that is already visible in the current link context.
    Existing(K),
    /// Loads a new module for the provided canonical key and target arch.
    Load {
        /// Canonical key that should identify the loaded module.
        key: K,
        /// Reader used to load the resolved ELF image.
        reader: Box<dyn ElfReader + 'cfg>,
    },
    /// Provides a synthetic module and any dependencies it should place after
    /// itself in the resolved dependency graph.
    Synthetic {
        /// Canonical key that should identify the synthetic module.
        key: K,
        /// Synthetic or externally retained module exposed for symbol lookup.
        module: ModuleHandle<Arch>,
        /// Dependencies resolved as part of this synthetic graph fragment.
        deps: Vec<ResolvedKey<'cfg, K, Arch>>,
    },
}

impl<'cfg, K, Arch: RelocationArch> ResolvedKey<'cfg, K, Arch> {
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

    /// Creates a result backed by a synthetic module.
    #[inline]
    pub fn synthetic(
        key: K,
        module: impl Into<ModuleHandle<Arch>>,
        deps: impl Into<Vec<ResolvedKey<'cfg, K, Arch>>>,
    ) -> Self {
        Self::Synthetic {
            key,
            module: module.into(),
            deps: deps.into(),
        }
    }
}

/// Runtime key-resolution policy used by [`super::super::Linker`].
pub trait KeyResolver<'cfg, K: Clone, Arch: RelocationArch = NativeArch> {
    /// Resolves the root key passed to a linker load operation.
    fn load_root(&mut self, req: &RootRequest<'_, K>) -> Result<ResolvedKey<'cfg, K, Arch>>;

    /// Resolves one `DT_NEEDED` dependency for an already scanned owner.
    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, K>,
    ) -> Result<ResolvedKey<'cfg, K, Arch>>;
}
