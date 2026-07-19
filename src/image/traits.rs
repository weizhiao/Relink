use crate::{
    arch::NativeArch,
    elf::{ElfLayout, ElfSymbol, SymbolLookup, SymbolTable},
    memory::ImageMemory,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::Arc,
    tls::{ModuleTls, TlsResolver},
};
use alloc::boxed::Box;
use core::any::Any;

/// Runtime symbol exports for a module.
///
/// Export backends may be backed by an ELF dynamic symbol table, an object export
/// table, kernel export metadata, or a caller-provided synthetic table.
pub trait SymbolExports<L: ElfLayout>: Send + Sync {
    /// Returns exported symbol entries when this backend can enumerate them.
    fn symbols(&self) -> &[ElfSymbol<L>];

    /// Returns the name for a symbol entry from this export table.
    fn symbol_name<'exports>(&'exports self, symbol: &ElfSymbol<L>) -> Option<&'exports str>;

    /// Looks up one exported symbol by name and optional version.
    fn lookup<'exports>(
        &'exports self,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'exports ElfSymbol<L>>;
}

#[inline]
pub(crate) fn exports_handle<L, E>(exports: E) -> Arc<dyn SymbolExports<L>>
where
    L: ElfLayout,
    E: SymbolExports<L> + 'static,
{
    Arc::from(Box::new(exports) as Box<dyn SymbolExports<L>>)
}

impl<L> SymbolExports<L> for SymbolTable<L>
where
    L: ElfLayout,
{
    #[inline]
    fn symbols(&self) -> &[ElfSymbol<L>] {
        self.view().symbols()
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

    /// Returns the runtime symbol exports for this module.
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout>;

    /// Returns this module's runtime memory view.
    fn memory(&self) -> &dyn ImageMemory;

    /// Returns TLS metadata when this module owns a TLS block.
    fn tls(&self) -> Option<ModuleTls> {
        None
    }

    /// Returns the runtime domain in which this module's addresses are meaningful.
    fn domain_id(&self) -> DomainId;
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
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        (**self).exports()
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        (**self).memory()
    }

    #[inline]
    fn tls(&self) -> Option<ModuleTls> {
        (**self).tls()
    }

    #[inline]
    fn domain_id(&self) -> DomainId {
        (**self).domain_id()
    }
}
