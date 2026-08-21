use crate::{
    arch::NativeArch,
    image::{LookupScope, RawDynamic},
    memory::{HostRegion, RegionAccess},
    relocation::{BindingMode, RelocationArch},
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
}

impl<D: Send + Sync + 'static, Arch, R, Tls> LinkerRelocationEvent<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(raw: RawDynamic<D, Arch, R, Tls>, scope: LookupScope<Arch, Tls>) -> Self {
        Self {
            raw,
            scope,
            binding: BindingMode::Default,
        }
    }

    #[inline]
    pub const fn raw(&self) -> &RawDynamic<D, Arch, R, Tls> {
        &self.raw
    }

    #[inline]
    pub const fn scope(&self) -> &LookupScope<Arch, Tls> {
        &self.scope
    }

    #[inline]
    pub fn scope_mut(&mut self) -> &mut LookupScope<Arch, Tls> {
        &mut self.scope
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
        LookupScope<Arch, Tls>,
        BindingMode,
    ) {
        (self.raw, self.scope, self.binding)
    }
}
