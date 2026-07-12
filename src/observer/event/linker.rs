use crate::{
    image::{LoadedCore, ModuleScope, RawDynamic},
    memory::{HostRegion, RegionAccess},
    relocation::{BindingMode, RelocationArch},
    tls::TlsResolver,
};
use alloc::vec::Vec;

/// Mutable event for one module's relocation policy.
pub struct LinkerRelocationEvent<
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
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

/// Mutable event for constructors scheduled by one linker transaction.
pub struct LinkerInitEvent<
    'event,
    K,
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    root_key: &'event K,
    root: &'event LoadedCore<D, Arch, R, Tls>,
    modules: &'event mut Vec<LoadedCore<D, Arch, R, Tls>>,
}

impl<'event, K, D: 'static, Arch, R, Tls> LinkerInitEvent<'event, K, D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        root_key: &'event K,
        root: &'event LoadedCore<D, Arch, R, Tls>,
        modules: &'event mut Vec<LoadedCore<D, Arch, R, Tls>>,
    ) -> Self {
        Self {
            root_key,
            root,
            modules,
        }
    }

    #[inline]
    pub const fn root_key(&self) -> &'event K {
        self.root_key
    }

    #[inline]
    pub const fn root(&self) -> &'event LoadedCore<D, Arch, R, Tls> {
        self.root
    }

    #[inline]
    pub fn modules(&self) -> &[LoadedCore<D, Arch, R, Tls>] {
        self.modules
    }

    #[inline]
    pub fn modules_mut(&mut self) -> &mut Vec<LoadedCore<D, Arch, R, Tls>> {
        self.modules
    }
}
