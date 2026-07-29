use super::{context::DirectDeps, storage::ModuleId};
use crate::{
    Result, arch::NativeArch, image::ModuleHandle, relocation::RelocationArch, tls::TlsResolver,
};
use alloc::vec::Vec;
use core::fmt;

/// One module detached from a link context by [`super::LinkContext::release`].
pub struct UnloadedModule<M, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    id: ModuleId,
    module: ModuleHandle<Arch, Tls>,
    direct_deps: DirectDeps,
    meta: M,
}

impl<M, Arch, Tls> UnloadedModule<M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) const fn new(
        id: ModuleId,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: DirectDeps,
        meta: M,
    ) -> Self {
        Self {
            id,
            module,
            direct_deps,
            meta,
        }
    }

    /// Returns the id the module had before it was detached.
    #[inline]
    pub const fn id(&self) -> ModuleId {
        self.id
    }

    /// Returns the retained module handle.
    #[inline]
    pub const fn module(&self) -> &ModuleHandle<Arch, Tls> {
        &self.module
    }

    /// Returns the module's former direct dependencies.
    #[inline]
    pub const fn direct_deps(&self) -> &DirectDeps {
        &self.direct_deps
    }

    /// Returns the module's user metadata.
    #[inline]
    pub const fn meta(&self) -> &M {
        &self.meta
    }

    /// Consumes the entry and returns all detached state.
    #[inline]
    pub fn into_parts(self) -> (ModuleId, ModuleHandle<Arch, Tls>, DirectDeps, M) {
        (self.id, self.module, self.direct_deps, self.meta)
    }
}

impl<M, Arch, Tls> fmt::Debug for UnloadedModule<M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnloadedModule")
            .field("id", &self.id)
            .field("name", &self.module.name())
            .field("direct_deps", &self.direct_deps.len())
            .finish_non_exhaustive()
    }
}

/// Modules made unreachable and detached by [`super::LinkContext::release`].
///
/// The collection retains the complete unload group so finalizers may still
/// call code in dependencies that were detached at the same time.
#[must_use = "detached modules should be finalized or handled explicitly"]
pub struct UnloadGroup<M, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Vec<UnloadedModule<M, Arch, Tls>>,
}

impl<M, Arch, Tls> UnloadGroup<M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) fn new(modules: Vec<UnloadedModule<M, Arch, Tls>>) -> Self {
        Self { modules }
    }

    /// Returns true when releasing the acquisition detached no modules.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Returns the number of detached modules.
    #[inline]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Returns detached modules in finalization order.
    #[inline]
    pub fn modules(&self) -> &[UnloadedModule<M, Arch, Tls>] {
        &self.modules
    }

    /// Consumes the collection without running finalizers.
    #[inline]
    pub fn into_modules(self) -> Vec<UnloadedModule<M, Arch, Tls>> {
        self.modules
    }
}

impl<M, Arch, Tls> UnloadGroup<M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    /// Consumes the collection and executes all finalizers.
    ///
    /// The complete unload group remains alive until every finalizer has run.
    /// Finalization continues after an error and returns the first failure.
    pub fn finalize(self) -> Result<()> {
        let mut error = None;
        for entry in &self.modules {
            if let Err(current) = entry.module.finalize()
                && error.is_none()
            {
                error = Some(current);
            }
        }
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<M, Arch, Tls> fmt::Debug for UnloadGroup<M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.modules).finish()
    }
}
