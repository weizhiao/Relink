use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfDynamicTag, ElfRelType, ElfSymbol, HashTable},
    image::{CoreInner, ElfCore},
    input::Path,
    os::{HostRegion, RegionAccess, VmAddr},
    relocation::{RelocValue, RelocationArch},
    segment::ElfSegments,
    sync::Arc,
    tls::{TlsModuleId, TlsTpOffset},
};
use alloc::boxed::Box;
use core::marker::PhantomData;

/// Runtime linker state change notification.
///
/// These states intentionally mirror the shape of the classic `r_debug.r_state`
/// values without requiring Relink to own an `r_debug` or `link_map` instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkActivity {
    /// The loaded module set is being extended.
    Add,
    /// The loaded module set is being reduced.
    Delete,
    /// The loaded module set is stable.
    Consistent,
}

/// A mutable `DT_DEBUG` dynamic entry discovered in an image.
///
/// The observer decides whether and how to patch it. This keeps debugger-facing
/// state such as `r_debug` and `link_map` owned by the embedding runtime.
pub struct DtDebugEntry<'a, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    addr: VmAddr,
    segments: &'a ElfSegments<R>,
    _marker: PhantomData<fn() -> Arch>,
}

impl<'a, Arch: RelocationArch, R: RegionAccess> DtDebugEntry<'a, Arch, R> {
    #[inline]
    pub(crate) const fn new(addr: VmAddr, segments: &'a ElfSegments<R>) -> Self {
        Self {
            addr,
            segments,
            _marker: PhantomData,
        }
    }

    /// Returns the runtime address of the `DT_DEBUG` dynamic entry.
    #[inline]
    pub const fn addr(&self) -> VmAddr {
        self.addr
    }

    /// Writes the runtime address of an externally owned `r_debug` object.
    #[inline]
    pub fn write_r_debug_addr(&self, addr: VmAddr) -> Result<()> {
        let entry = ElfDyn::<Arch::Layout>::new(ElfDynamicTag::DEBUG, addr.get());
        unsafe { self.segments.write_value(self.addr, RelocValue::new(entry)) }
    }
}

/// Ordinary symbol relocation binding event.
///
/// Observers may inspect the requested symbol and override the resolved address.
pub struct SymbolBindingEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    core: &'a ElfCore<D, Arch, R, H>,
    rel: &'a ElfRelType<Arch>,
    symbol: &'a ElfSymbol<Arch::Layout>,
    symbol_name: &'a str,
    resolved: Option<VmAddr>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, H>
    SymbolBindingEvent<'a, D, Arch, R, H>
{
    #[inline]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R, H>,
        rel: &'a ElfRelType<Arch>,
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
    pub const fn core(&self) -> &ElfCore<D, Arch, R, H> {
        self.core
    }

    /// Returns the relocation entry that requested this binding.
    #[inline]
    pub const fn rel(&self) -> &ElfRelType<Arch> {
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

/// IFUNC resolver binding event.
///
/// Non-native runtimes can execute the resolver in their guest environment and
/// provide the resolved address with [`IfuncBindingEvent::set_resolved_addr`].
pub struct IfuncBindingEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    core: &'a ElfCore<D, Arch, R, H>,
    rel: &'a ElfRelType<Arch>,
    resolver: VmAddr,
    resolved: Option<VmAddr>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, H>
    IfuncBindingEvent<'a, D, Arch, R, H>
{
    #[inline]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R, H>,
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
    pub const fn core(&self) -> &ElfCore<D, Arch, R, H> {
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
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    core: &'a ElfCore<D, Arch, R, H>,
    rel: &'a ElfRelType<Arch>,
    request: TlsDescBindingRequest,
    value: Option<TlsDescBindingValue>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, H>
    TlsDescBindingEvent<'a, D, Arch, R, H>
{
    #[inline]
    #[cfg(feature = "tls")]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R, H>,
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
    pub const fn core(&self) -> &ElfCore<D, Arch, R, H> {
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

/// Event emitted after a dynamic image has been relocated.
pub struct ModuleRelocatedEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    core: &'a ElfCore<D, Arch, R>,
    dynamic_addr: VmAddr,
    unload_hook: Option<SharedModuleUnloadHook<D, Arch, R>>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> ModuleRelocatedEvent<'a, D, Arch, R> {
    #[inline]
    pub(crate) const fn new(core: &'a ElfCore<D, Arch, R>, dynamic_addr: VmAddr) -> Self {
        Self {
            core,
            dynamic_addr,
            unload_hook: None,
        }
    }

    /// Returns the image core associated with this event.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R> {
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

    /// Installs a callback that will run when this module is dropped.
    ///
    /// The original relocation observer is usually gone by then, so unload
    /// handling is represented as a per-module hook captured during load.
    #[inline]
    pub fn set_unload_hook<F>(&mut self, hook: F)
    where
        F: for<'unload> Fn(ModuleUnloadEvent<'unload, D, Arch, R>) -> Result<()>
            + Send
            + Sync
            + 'static,
    {
        self.unload_hook = Some(Arc::from(Box::new(hook)
            as Box<
                dyn for<'unload> Fn(ModuleUnloadEvent<'unload, D, Arch, R>) -> Result<()>
                    + Send
                    + Sync,
            >));
    }

    #[inline]
    pub(crate) fn into_unload_hook(self) -> Option<SharedModuleUnloadHook<D, Arch, R>> {
        self.unload_hook
    }
}

pub(crate) type SharedModuleUnloadHook<
    D,
    Arch = NativeArch,
    R = HostRegion,
    H = HashTable<<Arch as RelocationArch>::Layout>,
> = Arc<dyn for<'a> Fn(ModuleUnloadEvent<'a, D, Arch, R, H>) -> Result<()> + Send + Sync>;

/// Module-level event emitted when a loaded image is being dropped.
pub struct ModuleUnloadEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    core: &'a CoreInner<D, Arch, R, H>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, H>
    ModuleUnloadEvent<'a, D, Arch, R, H>
{
    #[inline]
    pub(crate) const fn new(core: &'a CoreInner<D, Arch, R, H>) -> Self {
        Self { core }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.core.path
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.core.segments.base()
    }

    /// Returns the mapped segments that are still available during unload.
    #[inline]
    pub const fn segments(&self) -> &'a ElfSegments<R> {
        &self.core.segments
    }

    /// Returns the module user data.
    #[inline]
    pub const fn user_data(&self) -> &'a D {
        &self.core.user_data
    }
}
