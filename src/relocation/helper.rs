#[cfg(feature = "object")]
use crate::memory::VmOffset;
use crate::{
    Error, RelocReason, Result,
    elf::{ElfRelEntry, ElfRelType, ElfSymbol, SymbolEntry, SymbolTableView},
    hint::unlikely,
    image::{ElfCore, ModuleInstanceId, ModuleState},
    memory::{ImageMemory, RegionAccess, VmAddr},
    observer::{RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{
        BindingEffect, HandleResult, RelocationArch, RelocationEvent, SymDef, SymbolResolver,
    },
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
    pins: Vec<ModuleInstanceId>,
}

impl BindingDeps {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            providers: Vec::new(),
            pins: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn record(&mut self, effect: BindingEffect) {
        if let Some(provider) = effect.provider
            && !self.providers.contains(&provider)
        {
            self.providers.push(provider);
        }
        if let Some(pin) = effect.pin()
            && !self.pins.contains(&pin)
        {
            self.pins.push(pin);
        }
    }

    #[inline]
    pub(crate) fn install(self, state: &ModuleState) {
        if !self.providers.is_empty() || !self.pins.is_empty() {
            state.install_effects(self.providers, self.pins);
        }
    }
}

enum CachedDefinition<'find, Arch: RelocationArch> {
    Symbol(Option<SymDef<'find, Arch>>),
    TlsEntry(VmAddr),
}

struct SymbolCache<'find, Arch: RelocationArch> {
    index: usize,
    symbol: &'find ElfSymbol<Arch::Layout>,
    name: &'find [u8],
    definition: CachedDefinition<'find, Arch>,
}

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<
    'find,
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
    Obs: ?Sized,
    Memory = &'find ElfSegments<R>,
> {
    pub(crate) core: &'find ElfCore<D, Arch, R, Tls>,
    resolver: &'find SymbolResolver<'find, Arch>,
    symbol_cache: Option<SymbolCache<'find, Arch>>,
    bindings: BindingDeps,
    symbols: SymbolTableView<'find, Arch::Layout>,
    memory: Memory,
    pub(crate) observer: &'find mut Obs,
}

impl<'find, D, Arch, R, Tls, Obs, Memory> RelocHelper<'find, D, Arch, R, Tls, Obs, Memory>
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
        resolver: &'find SymbolResolver<'find, Arch>,
        bindings: BindingDeps,
        symbols: SymbolTableView<'find, Arch::Layout>,
        memory: Memory,
        observer: &'find mut Obs,
    ) -> Self {
        Self {
            core,
            resolver,
            symbol_cache: None,
            bindings,
            symbols,
            memory,
            observer,
        }
    }

    #[inline]
    pub(crate) fn into_bindings(self) -> BindingDeps {
        self.bindings
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
            self.resolver,
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
            self.resolver,
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
            self.resolver,
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
        let symbol = self
            .symbols
            .get_raw(r_sym)
            .expect("relocation symbol index is out of bounds");
        self.core.segments().base() + VmOffset::new(symbol.st_value())
    }

    #[inline]
    pub(crate) fn symbol_entry(&self, rel: &ElfRelType<Arch>) -> SymbolEntry<'find, Arch::Layout> {
        self.symbols.entry(rel.r_symbol())
    }

    #[inline]
    pub(crate) fn find_symdef<'a>(
        &'a self,
        symbol: &SymbolEntry<'a, Arch::Layout>,
    ) -> Option<SymDef<'a, Arch>> {
        self.resolver.find(symbol)
    }

    #[inline]
    pub(crate) fn find_copy_symdef<'a>(
        &'a self,
        symbol: &SymbolEntry<'a, Arch::Layout>,
    ) -> Option<(SymDef<'a, Arch>, BindingEffect)> {
        self.resolver.find_copy(symbol)
    }

    #[inline]
    pub(crate) fn record_binding(&mut self, effect: BindingEffect) {
        self.bindings.record(effect);
    }

    #[inline]
    pub(crate) fn bind_symbol_addr(&mut self, rel: &ElfRelType<Arch>) -> Result<Option<VmAddr>> {
        // Cache only ordinary bindings within this module's fixed lookup scope.
        // The definition depends on the symbol, not the relocation type.
        // COPY and TLS lookups use their separate paths. Keep the definition,
        // not its address: IFUNC and custom address resolvers still run per site.
        if self
            .symbol_cache
            .as_ref()
            .is_none_or(|cached| cached.index != rel.r_symbol())
        {
            let entry = self.symbol_entry(rel);
            let definition = if Tls::OVERRIDE_TLS_GET_ADDR && entry.name() == TLS_GET_ADDR_SYMBOL {
                CachedDefinition::TlsEntry(
                    self.core
                        .domain()
                        .id()
                        .tls_entry()
                        .expect("TLS entry override requires a TLS-enabled domain"),
                )
            } else {
                CachedDefinition::Symbol(self.resolver.find(&entry))
            };
            self.symbol_cache = Some(SymbolCache {
                index: rel.r_symbol(),
                symbol: entry.symbol(),
                name: entry.name(),
                definition,
            });
        }
        let cached = self.symbol_cache.as_ref().unwrap();
        let (resolved, effect) = match &cached.definition {
            CachedDefinition::TlsEntry(addr) => (Some(*addr), BindingEffect::default()),
            CachedDefinition::Symbol(definition) => {
                let effect = definition
                    .as_ref()
                    .map(|definition| definition.effect(&**self.core))
                    .unwrap_or_default();
                let resolved = definition
                    .as_ref()
                    .map(|definition| definition.resolve(&**self.core))
                    .transpose()?;
                (resolved, effect)
            }
        };
        let mut event =
            SymbolBindingEvent::new(self.core, Some(rel), cached.symbol, cached.name, resolved);
        self.observer.on_symbol_binding(&mut event)?;
        let resolved = event.into_resolved_addr();
        if resolved.is_some() {
            self.record_binding(effect);
        }
        Ok(resolved)
    }
}
