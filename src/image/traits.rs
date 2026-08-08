use super::module::ModuleState;
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfLayout, ElfSymbol, SymbolLookup, SymbolTable},
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    runtime::DomainId,
    sync::Arc,
    tls::{ModuleTls, TlsResolver},
};
use core::any::Any;

use super::search::ModuleSearch;

/// Runtime symbol exports for a module.
///
/// Export backends may be backed by an ELF dynamic symbol table, an object export
/// table, kernel export metadata, or a caller-provided synthetic table.
pub trait SymbolExports<L: ElfLayout>: Send + Sync {
    /// Visits symbols that can participate in exported-symbol lookup.
    fn for_each(&self, visitor: &mut dyn FnMut(&ElfSymbol<L>));

    /// Returns the name for a symbol entry from this export table.
    fn symbol_name<'exports>(&'exports self, symbol: &ElfSymbol<L>) -> Option<&'exports str>;

    /// Looks up one exported symbol by name and optional version.
    fn lookup<'exports>(
        &'exports self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<L>>;
}

impl<L> SymbolExports<L> for SymbolTable<L>
where
    L: ElfLayout,
{
    #[inline]
    fn for_each(&self, visitor: &mut dyn FnMut(&ElfSymbol<L>)) {
        self.hashtab.for_each(self.view(), visitor);
    }

    #[inline]
    fn symbol_name<'exports>(&'exports self, symbol: &ElfSymbol<L>) -> Option<&'exports str> {
        Some(self.strtab().get_str(symbol.st_name()))
    }

    #[inline]
    fn lookup<'exports>(
        &'exports self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<L>> {
        self.view().lookup(lookup)
    }
}

/// A runtime module that can satisfy symbol lookups during relocation.
///
/// Implementations may be backed by a loaded ELF image, a synthetic/virtual DSO,
/// or any other module that can expose ELF-like symbol definitions.
pub trait Module<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()>:
    Any + Send + Sync
{
    /// Returns the module name used for diagnostics.
    fn name(&self) -> &str;

    /// Returns the runtime domain in which this module's addresses are meaningful.
    fn domain_id(&self) -> DomainId;

    /// Returns metadata used when this module initiates another load.
    fn search(&self) -> Option<&ModuleSearch> {
        None
    }

    /// Returns the runtime symbol exports for this module.
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout>;

    /// Returns this module's runtime memory view.
    fn memory(&self) -> &dyn ImageMemory;

    /// Resolves one of this module's exported symbols to its runtime address.
    ///
    /// `symbol` must come from this module's [`SymbolExports`]. Implementations
    /// define how ordinary, absolute, TLS, IFUNC, and module-specific symbols
    /// become target-visible addresses.
    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr>;

    /// Returns TLS metadata when this module owns a TLS block.
    fn tls(&self) -> Option<ModuleTls> {
        None
    }

    /// Returns the canonical lifecycle state for this logical module.
    ///
    /// Wrappers around the same module must return the same stable state
    /// address. Relink uses it to coordinate initialization and finalization
    /// across wrappers around the same underlying module.
    fn state(&self) -> &ModuleState;

    /// Performs this module's initialization hook.
    ///
    /// Relink invokes this through [`ModuleHandle`](super::ModuleHandle), which
    /// guarantees that the hook runs at most once.
    fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// Performs this module's finalization hook.
    ///
    /// The module's owning allocation should invoke this through
    /// [`ModuleState::finalize`] from its `Drop` implementation. Core-backed ELF
    /// modules already do this in `CoreInner`.
    fn finalize(&self) -> Result<()> {
        Ok(())
    }
}

impl<M, Arch, Tls> Module<Arch, Tls> for Arc<M>
where
    M: Module<Arch, Tls> + ?Sized + 'static,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        (**self).name()
    }

    #[inline]
    fn domain_id(&self) -> DomainId {
        (**self).domain_id()
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        (**self).search()
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        (**self).exports()
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        (**self).memory()
    }

    #[inline]
    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr> {
        (**self).resolve_symbol(symbol)
    }

    #[inline]
    fn tls(&self) -> Option<ModuleTls> {
        (**self).tls()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        (**self).state()
    }

    #[inline]
    fn initialize(&self) -> Result<()> {
        (**self).initialize()
    }

    #[inline]
    fn finalize(&self) -> Result<()> {
        (**self).finalize()
    }
}
