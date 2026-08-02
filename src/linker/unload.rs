use super::storage::ModuleId;
use crate::{arch::NativeArch, image::ModuleHandle, relocation::RelocationArch, tls::TlsResolver};
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

/// One module detached from a link context by [`super::LinkContext::release`].
pub struct UnloadedModule<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    id: ModuleId,
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[ModuleId]>,
}

impl<Arch, Tls> UnloadedModule<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) const fn new(
        id: ModuleId,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleId]>,
    ) -> Self {
        Self {
            id,
            module,
            direct_deps,
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
    pub const fn direct_deps(&self) -> &[ModuleId] {
        &self.direct_deps
    }
}

impl<Arch, Tls> fmt::Debug for UnloadedModule<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnloadedModule")
            .field("id", &self.id)
            .field("name", &self.module().name())
            .field("direct_deps", &self.direct_deps.len())
            .finish_non_exhaustive()
    }
}

/// Modules made unreachable and detached by [`super::LinkContext::release`].
///
/// The collection retains the complete unload group so finalizers may still
/// call code in dependencies that were detached at the same time.
pub struct UnloadGroup<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Vec<UnloadedModule<Arch, Tls>>,
}

impl<Arch, Tls> UnloadGroup<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) fn new(modules: Vec<UnloadedModule<Arch, Tls>>) -> Self {
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
    pub fn modules(&self) -> &[UnloadedModule<Arch, Tls>] {
        &self.modules
    }

    /// Splits the collection into independently retained detached modules.
    ///
    /// Each returned entry releases its module when dropped.
    #[inline]
    pub fn into_modules(self) -> Vec<UnloadedModule<Arch, Tls>> {
        self.modules
    }
}

impl<Arch, Tls> fmt::Debug for UnloadGroup<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.modules).finish()
    }
}
