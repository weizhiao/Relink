#[cfg(feature = "object")]
use crate::memory::VmOffset;
use crate::{
    Error, RelocReason, Result,
    elf::{ElfRelEntry, ElfRelType, HashTable, SymbolEntry, SymbolTableView},
    hint::unlikely,
    image::{ElfCore, LookupScope, Module, ModuleInstanceId, ModuleScope, ModuleState},
    memory::{ImageMemory, RegionAccess, VmAddr},
    observer::{RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{HandleResult, RelocationArch, RelocationEvent, SymDef, SymbolResolver},
    segment::ElfSegments,
    tls::{TLS_GET_ADDR_SYMBOL, TlsResolver},
};
use alloc::vec::Vec;

/// Providers actually selected while relocating one module.
///
/// Collection is kept separate from [`ModuleState`] so a failed relocation
/// cannot leave lifetime edges installed for an image that was never published.
pub(crate) struct BindingDeps {
    providers: Vec<ModuleInstanceId>,
}

impl BindingDeps {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn record(&mut self, source: &ModuleState, provider: ModuleInstanceId) {
        if provider != source.instance_id() && !self.providers.contains(&provider) {
            self.providers.push(provider);
        }
    }

    #[inline]
    pub(crate) fn install(self, state: &ModuleState) {
        state.with_bindings(|bindings| {
            bindings.reserve(self.providers.len());
            for provider in self.providers {
                if !bindings.contains(&provider) {
                    bindings.push(provider);
                }
            }
        });
    }
}

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<
    'find,
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
    Obs: ?Sized,
    H = HashTable<<Arch as RelocationArch>::Layout>,
    Memory = &'find ElfSegments<R>,
> {
    pub(crate) core: &'find ElfCore<D, Arch, R, Tls>,
    resolver: SymbolResolver<'find, Arch, Tls>,
    bindings: BindingDeps,
    symbols: SymbolTableView<'find, Arch::Layout, H>,
    memory: Memory,
    pub(crate) observer: &'find mut Obs,
}

impl<'find, D: Send + Sync + 'static, Arch, R, Tls, Obs, H, Memory>
    RelocHelper<'find, D, Arch, R, Tls, Obs, H, Memory>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    Obs: RelocationObserver<Arch> + ?Sized,
    Memory: ImageMemory,
{
    pub(crate) fn new(
        core: &'find ElfCore<D, Arch, R, Tls>,
        resolver: SymbolResolver<'find, Arch, Tls>,
        bindings: BindingDeps,
        symbols: SymbolTableView<'find, Arch::Layout, H>,
        memory: Memory,
        observer: &'find mut Obs,
    ) -> Self {
        Self {
            core,
            resolver,
            bindings,
            symbols,
            memory,
            observer,
        }
    }

    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        LookupScope<Arch, Tls>,
        Option<ModuleScope<Arch, Tls>>,
        BindingDeps,
    ) {
        let (scope, global) = self.resolver.into_parts();
        (scope, global, self.bindings)
    }

    #[inline]
    pub(crate) fn memory(&self) -> &Memory {
        &self.memory
    }

    #[inline]
    pub(crate) fn handle_pre(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let mut event = RelocationEvent::new(
            self.core,
            rel,
            &self.resolver,
            &mut self.bindings,
            self.symbols,
        );
        self.observer.on_relocation_pre(&mut event)
    }

    #[cfg(feature = "object")]
    #[inline]
    pub(crate) fn handle_post(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let mut event = RelocationEvent::new(
            self.core,
            rel,
            &self.resolver,
            &mut self.bindings,
            self.symbols,
        );
        self.observer.on_relocation_post(&mut event)
    }

    #[inline]
    pub(crate) fn handle_fallback(
        &mut self,
        rel: &ElfRelType<Arch>,
        reason: RelocReason,
    ) -> Result<()> {
        let mut event = RelocationEvent::new(
            self.core,
            rel,
            &self.resolver,
            &mut self.bindings,
            self.symbols,
        );
        if matches!(reason, RelocReason::Unsupported)
            && !Arch::relocate_custom(&mut event)?.is_unhandled()
        {
            return Ok(());
        }
        if self.observer.on_relocation_post(&mut event)?.is_unhandled() {
            return Err(self.reloc_error(rel, reason));
        }
        Ok(())
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
                Some(self.symbols.entry(r_sym).name()),
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
        let symbol = self.symbols.entry(r_sym);
        self.core.base() + VmOffset::new(symbol.symbol().st_value())
    }

    #[inline]
    pub(crate) fn symbol_entry(&self, rel: &ElfRelType<Arch>) -> SymbolEntry<'find, Arch::Layout> {
        self.symbols.entry(rel.r_symbol())
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
    pub(crate) fn record_binding(&mut self, provider: Option<ModuleInstanceId>) {
        if let Some(provider) = provider {
            self.bindings.record(self.core.state(), provider);
        }
    }

    #[inline]
    pub(crate) fn bind_symbol_addr(
        &mut self,
        rel: &ElfRelType<Arch>,
        symbol: SymbolEntry<'_, Arch::Layout>,
    ) -> Result<Option<VmAddr>> {
        let (resolved, provider) =
            if Tls::OVERRIDE_TLS_GET_ADDR && symbol.name() == TLS_GET_ADDR_SYMBOL {
                (Some(self.core.tls_resolver().bind_tls_get_addr()?), None)
            } else {
                let definition = self.resolver.find(&symbol);
                let provider = definition.as_ref().and_then(SymDef::provider_id);
                let resolved = definition.as_ref().map(SymDef::resolve).transpose()?;
                (resolved, provider)
            };
        let mut event = SymbolBindingEvent::new(
            self.core,
            Some(rel),
            symbol.symbol(),
            symbol.name(),
            resolved,
        );
        self.observer.on_symbol_binding(&mut event)?;
        let resolved = event.into_resolved_addr();
        if resolved.is_some() {
            self.record_binding(provider);
        }
        Ok(resolved)
    }
}
