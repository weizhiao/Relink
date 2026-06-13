use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfSymbol, PreCompute, SymbolInfo, SymbolTable},
    memory::{VmAddr, VmOffset},
    relocation::RelocationArch,
    sync::Arc,
    tls::{TlsModuleId, TlsTpOffset},
};
use alloc::boxed::Box;
use core::{any::Any, ptr::NonNull};

/// Runtime symbol exports for a module.
///
/// Export backends may be backed by an ELF dynamic symbol table, an object export
/// table, kernel export metadata, or a caller-provided synthetic table.
pub trait SymbolExports<Arch: RelocationArch>: Send + Sync {
    fn lookup<'exports>(
        &'exports self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<Arch::Layout>>;
}

#[inline]
pub(crate) fn exports_handle<Arch, E>(exports: E) -> Arc<dyn SymbolExports<Arch>>
where
    Arch: RelocationArch,
    E: SymbolExports<Arch> + 'static,
{
    Arc::from(Box::new(exports) as Box<dyn SymbolExports<Arch>>)
}

impl<Arch> SymbolExports<Arch> for SymbolTable<Arch::Layout>
where
    Arch: RelocationArch,
{
    #[inline]
    fn lookup<'exports>(
        &'exports self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<Arch::Layout>> {
        self.view().lookup_filter(symbol, precompute)
    }
}

/// A runtime module that can satisfy symbol lookups during relocation.
///
/// Implementations may be backed by a loaded ELF image, a synthetic/virtual DSO,
/// or any other module that can expose ELF-like symbol definitions.
pub trait Module<Arch: RelocationArch = NativeArch>: Any + Send + Sync {
    /// Returns this module as [`Any`] for runtime type checks.
    fn as_any(&self) -> &dyn Any;

    /// Returns whether this module is backed by a loaded image.
    fn is_loaded(&self) -> bool {
        false
    }

    /// Returns the module name used for diagnostics.
    fn name(&self) -> &str;

    /// Looks up a relocatable symbol definition.
    fn lookup_symbol<'source>(
        &'source self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'source ElfSymbol<Arch::Layout>>;

    /// Returns the runtime base address used with `st_value`.
    fn base(&self) -> VmAddr;

    /// Reads bytes from the module image for COPY relocations.
    fn read_bytes(&self, offset: VmOffset, dst: &mut [u8]) -> Result<()>;

    /// Translates a module VM address into a host-accessible pointer.
    fn host_ptr(&self, _addr: VmAddr) -> Option<NonNull<u8>> {
        None
    }

    /// Returns the TLS module id, when this module owns TLS storage.
    fn tls_mod_id(&self) -> Option<TlsModuleId> {
        None
    }

    /// Returns the static TLS thread-pointer offset, when available.
    fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        None
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
    fn is_loaded(&self) -> bool {
        (**self).is_loaded()
    }

    #[inline]
    fn name(&self) -> &str {
        (**self).name()
    }

    #[inline]
    fn lookup_symbol<'source>(
        &'source self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'source ElfSymbol<Arch::Layout>> {
        (**self).lookup_symbol(symbol, precompute)
    }

    #[inline]
    fn base(&self) -> VmAddr {
        (**self).base()
    }

    #[inline]
    fn read_bytes(&self, offset: VmOffset, dst: &mut [u8]) -> Result<()> {
        (**self).read_bytes(offset, dst)
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        (**self).host_ptr(addr)
    }

    #[inline]
    fn tls_mod_id(&self) -> Option<TlsModuleId> {
        (**self).tls_mod_id()
    }

    #[inline]
    fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        (**self).tls_tp_offset()
    }
}
