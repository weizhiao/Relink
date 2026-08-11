use super::storage::ModuleId;
use crate::{
    arch::NativeArch,
    image::{LookupScope, Module, ModuleHandle},
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::fmt;

/// One module detached from a link context by [`super::LinkContext::release`].
pub struct UnloadedModule<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()>
{
    id: ModuleId,
    module: ModuleHandle<Arch, Tls>,
    _scope: Option<LookupScope<Arch, Tls>>,
    meta: Meta,
}

impl<Meta, Arch, Tls> UnloadedModule<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) const fn new(
        id: ModuleId,
        module: ModuleHandle<Arch, Tls>,
        scope: Option<LookupScope<Arch, Tls>>,
        meta: Meta,
    ) -> Self {
        Self {
            id,
            module,
            _scope: scope,
            meta,
        }
    }

    /// Returns the id the module had before it was detached.
    #[inline]
    pub const fn id(&self) -> ModuleId {
        self.id
    }

    /// Borrows the detached module while its unload group retains dependencies.
    #[inline]
    pub fn module(&self) -> &dyn Module<Arch, Tls> {
        self.module.as_dyn()
    }

    /// Returns metadata detached with this context entry.
    #[inline]
    pub const fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Consumes the entry and returns its context metadata.
    ///
    /// The module and retained lookup scope are dropped together so a bare
    /// module handle cannot outlive its relocation providers accidentally.
    #[inline]
    pub fn into_meta(self) -> Meta {
        self.meta
    }
}

impl<Meta, Arch, Tls> fmt::Debug for UnloadedModule<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnloadedModule")
            .field("id", &self.id)
            .field("name", &self.module().name())
            .finish_non_exhaustive()
    }
}

/// Modules made unreachable and detached by [`super::LinkContext::release`].
///
/// The collection retains the complete unload group so finalizers may still
/// call code in dependencies that were detached at the same time.
pub struct UnloadGroup<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Vec<UnloadedModule<Meta, Arch, Tls>>,
}

impl<Meta, Arch, Tls> UnloadGroup<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(super) fn new(modules: Vec<UnloadedModule<Meta, Arch, Tls>>) -> Self {
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
    pub fn modules(&self) -> &[UnloadedModule<Meta, Arch, Tls>] {
        &self.modules
    }
}

impl<Meta, Arch, Tls> fmt::Debug for UnloadGroup<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.modules).finish()
    }
}
