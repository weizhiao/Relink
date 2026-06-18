use crate::{
    arch::NativeArch,
    elf::{ElfLayout, ElfSymbol, PreCompute, SymbolInfo, SymbolTable},
    memory::ImageMemory,
    relocation::RelocationArch,
    sync::Arc,
    tls::{TlsModuleId, TlsTpOffset},
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

    fn lookup<'exports>(
        &'exports self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
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
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<L>> {
        self.view().lookup_filter(symbol, precompute)
    }
}

/// TLS metadata associated with a runtime module.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ModuleTls {
    mod_id: Option<TlsModuleId>,
    tp_offset: Option<TlsTpOffset>,
}

impl ModuleTls {
    /// No TLS metadata is available for the module.
    pub const NONE: Self = Self {
        mod_id: None,
        tp_offset: None,
    };

    /// Creates module TLS metadata from the registered dynamic and static TLS values.
    #[inline]
    pub const fn new(mod_id: Option<TlsModuleId>, tp_offset: Option<TlsTpOffset>) -> Self {
        Self { mod_id, tp_offset }
    }

    /// Returns the registered TLS module id, when available.
    #[inline]
    pub const fn mod_id(self) -> Option<TlsModuleId> {
        self.mod_id
    }

    /// Returns the static TLS thread-pointer offset, when available.
    #[inline]
    pub const fn tp_offset(self) -> Option<TlsTpOffset> {
        self.tp_offset
    }
}

/// A runtime module that can satisfy symbol lookups during relocation.
///
/// Implementations may be backed by a loaded ELF image, a synthetic/virtual DSO,
/// or any other module that can expose ELF-like symbol definitions.
pub trait Module<Arch: RelocationArch = NativeArch>: Any + Send + Sync {
    /// Returns this module as [`Any`] for runtime type checks.
    fn as_any(&self) -> &dyn Any;

    /// Returns the module name used for diagnostics.
    fn name(&self) -> &str;

    /// Returns the runtime symbol exports for this module.
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout>;

    /// Returns this module's runtime memory view.
    fn memory(&self) -> &dyn ImageMemory;

    /// Returns TLS metadata for this module.
    fn tls(&self) -> ModuleTls {
        ModuleTls::NONE
    }
}

impl<M, Arch> Module<Arch> for Arc<M>
where
    M: Module<Arch> + ?Sized + 'static,
    Arch: RelocationArch,
{
    #[inline]
    fn as_any(&self) -> &dyn Any {
        (**self).as_any()
    }

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
    fn tls(&self) -> ModuleTls {
        (**self).tls()
    }
}
