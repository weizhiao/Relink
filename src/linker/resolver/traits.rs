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
        key: K,
        reader: Box<dyn ElfReader + 'cfg>,
    },
}

impl<'cfg, K> ResolvedKey<'cfg, K> {
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

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
    fn load_root(&mut self, req: &RootRequest<'_, K>) -> Result<ResolvedKey<'cfg, K>>;

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, K>,
    ) -> Result<ResolvedKey<'cfg, K>>;
}
