use crate::{
    arch::NativeArch,
    image::{LookupScope, RawDynamic},
    memory::{HostRegion, RegionAccess},
    relocation::{BindingMode, LookupOrder, RelocationArch},
    tls::TlsResolver,
};

/// Mutable event for one module's relocation policy.
pub struct LinkerRelocationEvent<
    D: Send + Sync + 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    raw: RawDynamic<D, Arch, R, Tls>,
    scope: LookupScope<Arch, Tls>,
    binding: BindingMode,
    lookup_order: LookupOrder,
}

impl<D: Send + Sync + 'static, Arch, R, Tls> LinkerRelocationEvent<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        raw: RawDynamic<D, Arch, R, Tls>,
        scope: LookupScope<Arch, Tls>,
        lookup_order: LookupOrder,
    ) -> Self {
        Self {
            raw,
            scope,
            binding: BindingMode::Default,
            lookup_order,
        }
    }

    /// Returns the loaded image that is about to be relocated.
    #[inline]
    pub const fn raw(&self) -> &RawDynamic<D, Arch, R, Tls> {
        &self.raw
    }

    /// Returns the module's lookup scope for this relocation.
    ///
    /// Linker-global modules participate in relocation separately and are not
    /// retained by this scope.
    #[inline]
    pub const fn scope(&self) -> &LookupScope<Arch, Tls> {
        &self.scope
    }

    /// Returns the mutable lookup scope used to relocate this module.
    ///
    /// Linker-global modules are managed separately and are not part of this
    /// scope.
    #[inline]
    pub const fn scope_mut(&mut self) -> &mut LookupScope<Arch, Tls> {
        &mut self.scope
    }

    /// Returns the symbol-binding policy selected for this module.
    #[inline]
    pub const fn binding(&self) -> BindingMode {
        self.binding
    }

    /// Replaces the symbol-binding policy used for this module.
    #[inline]
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }

    /// Returns precedence between local and context-global symbol scopes.
    #[inline]
    pub const fn lookup_order(&self) -> LookupOrder {
        self.lookup_order
    }

    /// Replaces precedence between local and context-global symbol scopes.
    #[inline]
    pub fn set_lookup_order(&mut self, order: LookupOrder) {
        self.lookup_order = order;
    }

    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        RawDynamic<D, Arch, R, Tls>,
        LookupScope<Arch, Tls>,
        BindingMode,
        LookupOrder,
    ) {
        (self.raw, self.scope, self.binding, self.lookup_order)
    }
}
