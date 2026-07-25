use super::lifecycle::{LifecycleHandlers, LifecycleRunner};
use crate::{
    arch::NativeArch,
    elf::{ElfRelEntry, ElfRelType, ElfSymbol, HashTable, SymbolEntry, SymbolTableView},
    image::{ElfCore, ModuleScope},
    input::Path,
    lazy::LazyValues,
    memory::{HostRegion, RegionAccess, VmAddr},
    relocation::{RelocationArch, SymDef, SymbolResolver},
    tls::TlsResolver,
};

/// Context passed to relocation observer hooks.
///
/// This struct provides access to the relocation entry, the module being relocated,
/// and the current symbol resolution scope.
pub struct RelocationEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    rel: &'a ElfRelType<Arch>,
    resolver: &'a SymbolResolver<'a, ElfCore<D, Arch, R, Tls>, Arch, Tls>,
    symbols: SymbolTableView<'a, Arch::Layout, H>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>, H>
    RelocationEvent<'a, D, Arch, R, Tls, H>
{
    /// Construct a new `RelocationEvent`.
    #[inline]
    pub(crate) const fn new(
        rel: &'a ElfRelType<Arch>,
        resolver: &'a SymbolResolver<'a, ElfCore<D, Arch, R, Tls>, Arch, Tls>,
        symbols: SymbolTableView<'a, Arch::Layout, H>,
    ) -> Self {
        Self {
            rel,
            resolver,
            symbols,
        }
    }

    /// Access the relocation entry.
    #[inline]
    pub fn rel(&self) -> &ElfRelType<Arch> {
        self.rel
    }

    /// Access the core component where the relocation appears.
    #[inline]
    pub fn lib(&self) -> &ElfCore<D, Arch, R, Tls> {
        self.resolver.source()
    }

    /// Access the current resolution scope.
    #[inline]
    pub fn scope(&self) -> &ModuleScope<Arch, Tls> {
        self.resolver.scope()
    }

    /// Returns values supplied by the lazy binder, when active.
    #[inline]
    pub fn lazy(&self) -> Option<LazyValues> {
        self.lib().inner.runtime().lazy_values()
    }

    /// Access a symbol table entry by index for this relocation context.
    #[inline]
    pub fn symbol(&self, r_sym: usize) -> SymbolEntry<'a, Arch::Layout> {
        self.symbols.symbol_idx(r_sym)
    }

    /// Access the symbol referenced by the current relocation, if it has one.
    #[inline]
    pub fn relocation_symbol(&self) -> Option<SymbolEntry<'a, Arch::Layout>> {
        let r_sym = self.rel.r_symbol();
        (r_sym != 0).then(|| self.symbol(r_sym))
    }

    /// Find symbol definition in the current scope.
    #[inline]
    pub fn find_symdef(&self, r_sym: usize) -> Option<SymDef<'a, Arch, Tls>> {
        self.resolver.find(&self.symbol(r_sym))
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
    pub const fn core(&self) -> &'a ElfCore<D, Arch, R, Tls> {
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
    lifecycle: LifecycleHandlers,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    DynamicRelocatedEvent<'a, D, Arch, R, Tls>
{
    #[inline]
    pub(crate) const fn new(
        core: &'a ElfCore<D, Arch, R, Tls>,
        dynamic_addr: VmAddr,
        initializer: LifecycleRunner,
        finalizer: LifecycleRunner,
    ) -> Self {
        Self {
            core,
            dynamic_addr,
            lifecycle: LifecycleHandlers::new(initializer, finalizer),
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

    /// Returns mutable lifecycle setup for initialization and finalization.
    #[inline]
    pub fn lifecycle_mut(&mut self) -> &mut LifecycleHandlers {
        &mut self.lifecycle
    }

    #[inline]
    pub(crate) fn into_lifecycle(self) -> LifecycleHandlers {
        self.lifecycle
    }
}
