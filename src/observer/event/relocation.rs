use super::lifecycle::{Finalizer, FiniEvent};
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfRelType, ElfSymbol, Lifecycle},
    image::ElfCore,
    input::Path,
    memory::{HostRegion, RegionAccess, VmAddr},
    relocation::RelocationArch,
    tls::TlsResolver,
};

/// Ordinary symbol relocation binding event.
///
/// Observers may inspect the requested symbol and override the resolved address.
pub struct SymbolBindingEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    core: &'a ElfCore<D, Arch, R, Tls>,
    rel: Option<&'a ElfRelType<Arch>>,
    symbol: &'a ElfSymbol<Arch::Layout>,
    symbol_name: &'a str,
    resolved: Option<VmAddr>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    SymbolBindingEvent<'a, D, Arch, R, Tls>
{
    #[inline]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R, Tls>,
        rel: Option<&'a ElfRelType<Arch>>,
        symbol: &'a ElfSymbol<Arch::Layout>,
        symbol_name: &'a str,
        resolved: Option<VmAddr>,
    ) -> Self {
        Self {
            core,
            rel,
            symbol,
            symbol_name,
            resolved,
        }
    }

    /// Returns the image core associated with this binding.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R, Tls> {
        self.core
    }

    /// Returns the relocation entry that requested this binding, when the
    /// binding is tied to one concrete relocation.
    #[inline]
    pub const fn rel(&self) -> Option<&ElfRelType<Arch>> {
        self.rel
    }

    /// Returns the symbol table entry referenced by the relocation.
    #[inline]
    pub const fn symbol(&self) -> &ElfSymbol<Arch::Layout> {
        self.symbol
    }

    /// Returns the symbol name referenced by the relocation.
    #[inline]
    pub const fn symbol_name(&self) -> &'a str {
        self.symbol_name
    }

    /// Returns the currently resolved address, if any.
    #[inline]
    pub const fn resolved_addr(&self) -> Option<VmAddr> {
        self.resolved
    }

    /// Sets the resolved address.
    #[inline]
    pub fn set_resolved_addr(&mut self, addr: VmAddr) {
        self.resolved = Some(addr);
    }

    /// Clears the resolved address.
    #[inline]
    pub fn clear_resolved_addr(&mut self) {
        self.resolved = None;
    }

    #[inline]
    pub(crate) const fn into_resolved_addr(self) -> Option<VmAddr> {
        self.resolved
    }
}

/// Event emitted after a dynamic image has been relocated.
pub struct DynamicRelocatedEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    core: &'a ElfCore<D, Arch, R, Tls>,
    dynamic_addr: VmAddr,
    finalizer: Finalizer,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    DynamicRelocatedEvent<'a, D, Arch, R, Tls>
{
    #[inline]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R, Tls>,
        dynamic_addr: VmAddr,
        finalizer: Finalizer,
    ) -> Self {
        Self {
            core,
            dynamic_addr,
            finalizer,
        }
    }

    /// Returns the image core associated with this event.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R, Tls> {
        self.core
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.core.path()
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

    /// Returns the runtime address of the first dynamic entry.
    #[inline]
    pub const fn dynamic_addr(&self) -> VmAddr {
        self.dynamic_addr
    }

    /// Returns the finalization lifecycle that will be run when the initialized
    /// image is dropped.
    #[inline]
    pub fn fini(&self) -> &Lifecycle {
        self.finalizer.lifecycle()
    }

    /// Returns mutable finalization lifecycle addresses.
    #[inline]
    pub fn fini_mut(&mut self) -> &mut Lifecycle {
        self.finalizer.lifecycle_mut()
    }

    /// Installs a hook that runs immediately before finalization functions.
    #[inline]
    pub fn set_fini_hook<F>(&mut self, hook: F)
    where
        F: for<'event> Fn(&mut FiniEvent<'event>) -> Result<()> + Send + Sync + 'static,
    {
        self.finalizer.set_hook(hook);
    }

    #[inline]
    pub(crate) fn into_finalizer(self) -> Finalizer {
        self.finalizer
    }
}
