#[cfg(feature = "object")]
use crate::memory::VmOffset;
use crate::{
    Error, RelocReason, Result,
    elf::{ElfRelEntry, ElfRelType, HashTable, SymbolEntry, SymbolTableView},
    hint::unlikely,
    image::{ElfCore, ModuleScope},
    memory::{ImageMemory, RegionAccess, VmAddr},
    observer::{RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{HandleResult, RelocationArch, RelocationEvent, SymDef, SymbolResolver},
    segment::ElfSegments,
    tls::{TLS_GET_ADDR_SYMBOL, TlsResolver},
};

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<
    'find,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
    Obs: ?Sized,
    H = HashTable<<Arch as RelocationArch>::Layout>,
    Memory = &'find ElfSegments<R>,
> {
    pub(crate) core: &'find ElfCore<D, Arch, R, Tls>,
    resolver: SymbolResolver<'find, ElfCore<D, Arch, R, Tls>, Arch, Tls>,
    symbols: SymbolTableView<'find, Arch::Layout, H>,
    memory: Memory,
    pub(crate) observer: &'find mut Obs,
}

impl<'find, D, Arch, R, Tls, Obs, H, Memory> RelocHelper<'find, D, Arch, R, Tls, Obs, H, Memory>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch> + ?Sized,
    Memory: ImageMemory,
{
    pub(crate) fn new(
        resolver: SymbolResolver<'find, ElfCore<D, Arch, R, Tls>, Arch, Tls>,
        symbols: SymbolTableView<'find, Arch::Layout, H>,
        memory: Memory,
        observer: &'find mut Obs,
    ) -> Self {
        let core = resolver.source();
        Self {
            core,
            resolver,
            symbols,
            memory,
            observer,
        }
    }

    #[inline]
    pub(crate) fn into_scope(self) -> ModuleScope<Arch, Tls> {
        self.resolver.into_scope()
    }

    #[inline]
    pub(crate) fn memory(&self) -> &Memory {
        &self.memory
    }

    #[inline]
    pub(crate) fn handle_pre(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let hctx = RelocationEvent::new(rel, &self.resolver, self.symbols);
        self.observer.on_relocation_pre(&hctx)
    }

    #[inline]
    pub(crate) fn handle_post(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let hctx = RelocationEvent::new(rel, &self.resolver, self.symbols);
        self.observer.on_relocation_post(&hctx)
    }

    #[cold]
    pub(crate) fn reloc_error(&self, rel: &ElfRelType<Arch>, reason: RelocReason) -> Error {
        let r_type_str = Arch::rel_type_to_str(rel.r_type());
        let r_sym = rel.r_symbol();
        if unlikely(r_sym == 0) {
            relocate_context_error(self.core.name(), r_type_str, None, reason)
        } else {
            relocate_context_error(
                self.core.name(),
                r_type_str,
                Some(self.symbols.symbol_idx(r_sym).name()),
                reason,
            )
        }
    }

    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn symbol_addr(&self, r_sym: usize) -> VmAddr {
        if r_sym == 0 {
            return VmAddr::null();
        }
        let symbol = self.symbols.symbol_idx(r_sym);
        self.core.base() + VmOffset::new(symbol.symbol().st_value())
    }

    #[inline]
    pub(crate) fn symbol_entry(&self, rel: &ElfRelType<Arch>) -> SymbolEntry<'find, Arch::Layout> {
        self.symbols.symbol_idx(rel.r_symbol())
    }

    #[inline]
    pub(crate) fn find_symdef<'a>(
        &'a self,
        symbol: &SymbolEntry<'a, Arch::Layout>,
    ) -> Option<SymDef<'a, Arch, Tls>> {
        self.resolver.find(symbol)
    }

    #[inline]
    pub(crate) fn find_copy_symdef<'a>(
        &'a self,
        symbol: &SymbolEntry<'a, Arch::Layout>,
    ) -> Option<SymDef<'a, Arch, Tls>> {
        self.resolver.find_copy(symbol)
    }

    #[inline]
    pub(crate) fn resolve_symbol_addr(
        &self,
        symbol: &SymbolEntry<'_, Arch::Layout>,
        symdef: Option<&SymDef<'_, Arch, Tls>>,
    ) -> Result<Option<VmAddr>> {
        Ok(
            if Tls::OVERRIDE_TLS_GET_ADDR && symbol.name() == TLS_GET_ADDR_SYMBOL {
                Some(self.core.tls_resolver().bind_tls_get_addr()?)
            } else {
                symdef
                    .map(|symdef| symdef.resolve(self.core.executor()))
                    .transpose()?
            },
        )
    }

    #[inline]
    pub(crate) fn bind_symbol_addr(
        &mut self,
        rel: &ElfRelType<Arch>,
        symbol: &SymbolEntry<'_, Arch::Layout>,
        resolved: Option<VmAddr>,
    ) -> Result<Option<VmAddr>> {
        let mut event = SymbolBindingEvent::new(
            self.core,
            Some(rel),
            symbol.symbol(),
            symbol.name(),
            resolved,
        );
        self.observer.on_symbol_binding(&mut event)?;
        Ok(event.into_resolved_addr())
    }
}
