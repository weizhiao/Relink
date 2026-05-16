use crate::{
    Result,
    input::ElfReader,
    linker::{DependencyRequest, RootRequest},
};
use alloc::boxed::Box;

/// A key-resolution result chosen by caller policy.
pub enum ResolvedKey<'cfg, K> {
    /// Reuses a module that is already visible in the current link context.
    Existing(K),
    /// Loads a new module for the provided canonical key and target arch.
    Load {
        /// Canonical key that should identify the loaded module.
        key: K,
        /// Reader used to load the resolved ELF image.
        reader: Box<dyn ElfReader + 'cfg>,
    },
}

impl<'cfg, K> ResolvedKey<'cfg, K> {
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
}

/// Runtime key-resolution policy used by [`super::super::Linker`].
pub trait KeyResolver<'cfg, K: Clone> {
    /// Resolves the root key passed to a linker load operation.
    fn load_root(&mut self, req: &RootRequest<'_, K>) -> Result<ResolvedKey<'cfg, K>>;

    /// Resolves one `DT_NEEDED` dependency for an already scanned owner.
    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, K>,
    ) -> Result<ResolvedKey<'cfg, K>>;
}
