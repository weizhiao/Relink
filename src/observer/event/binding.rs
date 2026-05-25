use crate::{
    arch::NativeArch,
    elf::ElfRelType,
    image::ElfCore,
    os::{HostRegion, RegionAccess, VmAddr},
    relocation::RelocationArch,
    tls::{TlsModuleId, TlsTpOffset},
};

/// IFUNC resolver binding event.
///
/// Non-native runtimes can execute the resolver in their guest environment and
/// provide the resolved address with [`IfuncBindingEvent::set_resolved_addr`].
pub struct IfuncBindingEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    core: &'a ElfCore<D, Arch, R>,
    rel: &'a ElfRelType<Arch>,
    resolver: VmAddr,
    resolved: Option<VmAddr>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> IfuncBindingEvent<'a, D, Arch, R> {
    #[inline]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R>,
        rel: &'a ElfRelType<Arch>,
        resolver: VmAddr,
    ) -> Self {
        Self {
            core,
            rel,
            resolver,
            resolved: None,
        }
    }

    /// Returns the image core associated with this binding.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R> {
        self.core
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.core.base()
    }

    /// Returns whether an absolute address is covered by this image.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        self.core.contains_addr(addr)
    }

    /// Returns the relocation entry that requested this binding.
    #[inline]
    pub const fn rel(&self) -> &ElfRelType<Arch> {
        self.rel
    }

    /// Returns the IFUNC resolver runtime address.
    #[inline]
    pub const fn resolver(&self) -> VmAddr {
        self.resolver
    }

    /// Returns the observer-provided resolved address, if one was set.
    #[inline]
    pub const fn resolved_addr(&self) -> Option<VmAddr> {
        self.resolved
    }

    /// Sets the IFUNC result address.
    #[inline]
    pub fn set_resolved_addr(&mut self, addr: VmAddr) {
        self.resolved = Some(addr);
    }

    #[inline]
    pub(crate) const fn into_resolved_addr(self) -> Option<VmAddr> {
        self.resolved
    }
}

/// Input data for a TLSDESC relocation binding.
#[derive(Clone, Copy, Debug)]
pub struct TlsDescBindingRequest {
    symbol_value: usize,
    addend: isize,
    module_id: Option<TlsModuleId>,
    tp_offset: Option<TlsTpOffset>,
    tls_get_addr: VmAddr,
}

impl TlsDescBindingRequest {
    /// Creates a TLSDESC binding request.
    #[inline]
    pub const fn new(
        symbol_value: usize,
        addend: isize,
        module_id: Option<TlsModuleId>,
        tp_offset: Option<TlsTpOffset>,
        tls_get_addr: VmAddr,
    ) -> Self {
        Self {
            symbol_value,
            addend,
            module_id,
            tp_offset,
            tls_get_addr,
        }
    }

    /// Symbol value from the TLS symbol referenced by the relocation.
    #[inline]
    pub const fn symbol_value(&self) -> usize {
        self.symbol_value
    }

    /// Relocation addend.
    #[inline]
    pub const fn addend(&self) -> isize {
        self.addend
    }

    /// Dynamic TLS module id when the symbol has one.
    #[inline]
    pub const fn module_id(&self) -> Option<TlsModuleId> {
        self.module_id
    }

    /// Static TLS thread-pointer offset when available.
    #[inline]
    pub const fn tp_offset(&self) -> Option<TlsTpOffset> {
        self.tp_offset
    }

    /// Address of the loader-provided `__tls_get_addr` entry point.
    #[inline]
    pub const fn tls_get_addr(&self) -> VmAddr {
        self.tls_get_addr
    }
}

/// Two-word TLSDESC value produced by a binding observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsDescBindingValue {
    resolver: VmAddr,
    arg: usize,
}

impl TlsDescBindingValue {
    /// Creates a TLSDESC pair.
    #[inline]
    pub const fn new(resolver: VmAddr, arg: usize) -> Self {
        Self { resolver, arg }
    }

    /// Resolver function pointer written to the first TLSDESC word.
    #[inline]
    pub const fn resolver(&self) -> VmAddr {
        self.resolver
    }

    /// Resolver argument written to the second TLSDESC word.
    #[inline]
    pub const fn arg(&self) -> usize {
        self.arg
    }
}

/// TLSDESC relocation binding event.
pub struct TlsDescBindingEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    core: &'a ElfCore<D, Arch, R>,
    rel: &'a ElfRelType<Arch>,
    request: TlsDescBindingRequest,
    value: Option<TlsDescBindingValue>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> TlsDescBindingEvent<'a, D, Arch, R> {
    #[inline]
    #[cfg(feature = "tls")]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R>,
        rel: &'a ElfRelType<Arch>,
        request: TlsDescBindingRequest,
    ) -> Self {
        Self {
            core,
            rel,
            request,
            value: None,
        }
    }

    /// Returns the image core associated with this binding.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R> {
        self.core
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.core.base()
    }

    /// Returns whether an absolute address is covered by this image.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        self.core.contains_addr(addr)
    }

    /// Returns the relocation entry that requested this binding.
    #[inline]
    pub const fn rel(&self) -> &ElfRelType<Arch> {
        self.rel
    }

    /// Returns the TLSDESC request payload.
    #[inline]
    pub const fn request(&self) -> TlsDescBindingRequest {
        self.request
    }

    /// Returns the observer-provided TLSDESC value, if one was set.
    #[inline]
    pub const fn value(&self) -> Option<TlsDescBindingValue> {
        self.value
    }

    /// Sets the TLSDESC value.
    #[inline]
    pub fn set_value(&mut self, value: TlsDescBindingValue) {
        self.value = Some(value);
    }

    #[inline]
    #[cfg(feature = "tls")]
    pub(crate) const fn into_value(self) -> Option<TlsDescBindingValue> {
        self.value
    }
}
