use crate::{
    elf::{ElfSymbol, PreCompute, SymbolInfo, SymbolTable},
    relocation::RelocationArch,
    sync::Arc,
};
use alloc::boxed::Box;
#[cfg(feature = "object")]
use core::marker::PhantomData;

/// Runtime symbol exports for a module.
///
/// Export backends may be backed by an ELF dynamic symbol table, an object export
/// table, kernel export metadata, or a caller-provided synthetic table.
pub(crate) trait SymbolExports<Arch: RelocationArch>: Send + Sync {
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

#[cfg(feature = "object")]
pub(crate) struct EmptyExports<Arch: RelocationArch> {
    _marker: PhantomData<fn() -> Arch>,
}

#[cfg(feature = "object")]
impl<Arch: RelocationArch> EmptyExports<Arch> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[cfg(feature = "object")]
impl<Arch: RelocationArch> SymbolExports<Arch> for EmptyExports<Arch> {
    #[inline]
    fn lookup<'exports>(
        &'exports self,
        _symbol: &SymbolInfo<'_>,
        _precompute: &mut PreCompute,
    ) -> Option<&'exports ElfSymbol<Arch::Layout>> {
        None
    }
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
