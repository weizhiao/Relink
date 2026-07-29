use crate::{
    arch::NativeArch,
    image::{ModuleScope, RawDynamic},
    memory::{HostRegion, RegionAccess},
    relocation::{BindingMode, RelocationArch},
    tls::TlsResolver,
};

/// Mutable event for one module's relocation policy.
pub struct LinkerRelocationEvent<
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    raw: RawDynamic<D, Arch, R, Tls>,
    scope: ModuleScope<Arch, Tls>,
    binding: BindingMode,
}

impl<D: 'static, Arch, R, Tls> LinkerRelocationEvent<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(raw: RawDynamic<D, Arch, R, Tls>, scope: &ModuleScope<Arch, Tls>) -> Self {
        Self {
            raw,
            scope: scope.clone(),
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub const fn raw(&self) -> &RawDynamic<D, Arch, R, Tls> {
        &self.raw
    }

    #[inline]
    pub const fn scope(&self) -> &ModuleScope<Arch, Tls> {
        &self.scope
    }

    #[inline]
    pub fn set_scope(&mut self, scope: ModuleScope<Arch, Tls>) {
        self.scope = scope;
    }

    #[inline]
    pub const fn binding(&self) -> BindingMode {
        self.binding
    }

    #[inline]
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }

    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        RawDynamic<D, Arch, R, Tls>,
        ModuleScope<Arch, Tls>,
        BindingMode,
    ) {
        (self.raw, self.scope, self.binding)
    }
}
