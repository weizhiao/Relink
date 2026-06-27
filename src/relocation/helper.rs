use crate::{
    Error, RelocReason, Result,
    elf::{
        ElfRelEntry, ElfRelType, ElfSymbol, ElfSymbolType, HashTable, SymbolInfo, SymbolTableView,
    },
    hint::{likely, unlikely},
    image::{ElfCore, Module, ModuleScope, SymbolLookup},
    logging,
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    observer::{RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{HandleResult, RelocationArch, RelocationContext, RelocationHandler},
    runtime::{CodeContext, CodeExecutor},
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
    PreH: ?Sized,
    PostH: ?Sized,
    Obs: ?Sized,
    H = HashTable<<Arch as RelocationArch>::Layout>,
    Memory = &'find ElfSegments<R>,
> {
    pub(crate) core: &'find ElfCore<D, Arch, R, Tls>,
    symbols: SymbolTableView<'find, Arch::Layout, H>,
    memory: Memory,
    pub(crate) scope: ModuleScope<Arch, Tls>,
    pub(crate) pre_handler: &'find PreH,
    pub(crate) post_handler: &'find PostH,
    pub(crate) observer: &'find mut Obs,
    pub(crate) executor: &'find dyn CodeExecutor<Arch>,
}

impl<'find, D, Arch, R, Tls, PreH, PostH, Obs, H, Memory>
    RelocHelper<'find, D, Arch, R, Tls, PreH, PostH, Obs, H, Memory>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    PreH: RelocationHandler<Arch> + ?Sized,
    PostH: RelocationHandler<Arch> + ?Sized,
    Obs: RelocationObserver<Arch> + ?Sized,
    Memory: ImageMemory,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        core: &'find ElfCore<D, Arch, R, Tls>,
        symbols: SymbolTableView<'find, Arch::Layout, H>,
        memory: Memory,
        scope: ModuleScope<Arch, Tls>,
        pre_handler: &'find PreH,
        post_handler: &'find PostH,
        observer: &'find mut Obs,
        executor: &'find dyn CodeExecutor<Arch>,
    ) -> Self {
        Self {
            core,
            symbols,
            memory,
            scope,
            pre_handler,
            post_handler,
            observer,
            executor,
        }
    }

    #[inline]
    pub(crate) fn memory(&self) -> &Memory {
        &self.memory
    }

    #[inline]
    pub(crate) fn handle_pre(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let hctx = RelocationContext::new(rel, self.core, self.symbols, &self.scope);
        self.pre_handler.handle(&hctx)
    }

    #[inline]
    pub(crate) fn handle_post(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let hctx = RelocationContext::new(rel, self.core, self.symbols, &self.scope);
        self.post_handler.handle(&hctx)
    }

    #[cold]
    pub(crate) fn reloc_error(&self, rel: &ElfRelType<Arch>, reason: RelocReason) -> Error {
        let r_type_str = Arch::rel_type_to_str(rel.r_type());
        let r_sym = rel.r_symbol();
        if r_sym == 0 {
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
        let symbol = self.symbols.symbol_idx(r_sym);
        self.core.base() + VmOffset::new(symbol.symbol().st_value())
    }

    #[inline]
    pub(crate) fn find_symdef(
        &mut self,
        rel: &ElfRelType<Arch>,
    ) -> Result<SymbolResolution<'_, Arch, Tls>> {
        let symbol = self.symbols.symbol_idx(rel.r_symbol());
        let runtime_addr = if Tls::OVERRIDE_TLS_GET_ADDR && symbol.name() == TLS_GET_ADDR_SYMBOL {
            Some(Tls::bind_tls_get_addr()?)
        } else {
            None
        };

        let symdef = if runtime_addr.is_none() {
            find_symdef_impl(
                self.core,
                &self.scope,
                symbol.symbol(),
                symbol.info(),
                self.core.symbolic(),
            )
        } else {
            None
        };
        let resolved = if let Some(addr) = runtime_addr {
            Some(addr)
        } else if let Some(symdef) = symdef.as_ref() {
            Some(symdef.resolve_addr(self.executor)?)
        } else {
            None
        };
        let mut event = SymbolBindingEvent::new(
            self.core,
            Some(rel),
            symbol.symbol(),
            symbol.name(),
            resolved,
        );
        self.observer.on_symbol_binding(&mut event)?;
        Ok(SymbolResolution {
            requested: symbol.symbol(),
            symdef,
            resolved_addr: event.into_resolved_addr(),
        })
    }
}

pub(crate) struct SymbolResolution<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    requested: &'lib ElfSymbol<Arch::Layout>,
    symdef: Option<SymDef<'lib, Arch, Tls>>,
    resolved_addr: Option<VmAddr>,
}

impl<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch>> SymbolResolution<'lib, Arch, Tls> {
    #[inline]
    pub(crate) fn requested_symbol(&self) -> &'lib ElfSymbol<Arch::Layout> {
        self.requested
    }

    #[inline]
    pub(crate) fn symdef(&self) -> Option<&SymDef<'lib, Arch, Tls>> {
        self.symdef.as_ref()
    }

    #[inline]
    pub(crate) fn resolved_addr(&self) -> Option<VmAddr> {
        self.resolved_addr
    }
}

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub struct SymDef<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch> = ()> {
    pub(crate) sym: Option<&'lib ElfSymbol<Arch::Layout>>,
    pub(crate) source: &'lib dyn Module<Arch, Tls>,
}

impl<'lib, Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> SymDef<'lib, Arch, Tls> {
    #[inline]
    pub(crate) fn new(
        sym: Option<&'lib ElfSymbol<Arch::Layout>>,
        source: &'lib dyn Module<Arch, Tls>,
    ) -> Self {
        Self { sym, source }
    }

    /// Computes the symbol address (base + st_value).
    ///
    /// For regular symbols, returns base + st_value.
    /// For IFUNC symbols, returns the resolver address without executing it.
    /// For undefined weak symbols, returns null.
    pub(crate) fn addr(&self) -> VmAddr {
        if likely(self.sym.is_some()) {
            let memory = self.source.memory();
            let base = memory.base();
            let sym = unsafe { self.sym.unwrap_unchecked() };
            base + VmOffset::new(sym.st_value())
        } else {
            // 未定义的弱符号返回null
            VmAddr::null()
        }
    }

    #[inline]
    pub(crate) fn resolve_addr(&self, executor: &dyn CodeExecutor<Arch>) -> Result<VmAddr> {
        let addr = self.addr();
        if unlikely(self.is_ifunc()) {
            self.resolve_ifunc_addr(executor, addr)
        } else {
            Ok(addr)
        }
    }

    #[cold]
    #[inline(never)]
    fn resolve_ifunc_addr(
        &self,
        executor: &dyn CodeExecutor<Arch>,
        resolver: VmAddr,
    ) -> Result<VmAddr> {
        executor.resolve_ifunc(
            CodeContext::<Arch>::new(self.source.name(), self.source.memory()),
            resolver,
        )
    }

    #[inline]
    pub(crate) fn is_ifunc(&self) -> bool {
        self.sym
            .is_some_and(|sym| sym.symbol_type() == ElfSymbolType::GNU_IFUNC)
    }

    #[inline]
    pub fn symbol(&self) -> Option<&'lib ElfSymbol<Arch::Layout>> {
        self.sym
    }

    #[inline]
    pub fn source(&self) -> &'lib dyn Module<Arch, Tls> {
        self.source
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls(&self) -> crate::image::ModuleTls {
        self.source.tls()
    }

    #[inline]
    pub(crate) fn read_bytes(&self, offset: VmOffset, dst: &mut [u8]) -> Result<()> {
        let memory = self.source.memory();
        memory.read_bytes(memory.base() + offset, dst)
    }
}

#[cold]
fn weak_undef<'lib, Arch, Tls, Source>(
    source: &'lib Source,
    sym: &'lib ElfSymbol<Arch::Layout>,
) -> Option<SymDef<'lib, Arch, Tls>>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
    Source: Module<Arch, Tls>,
{
    if sym.is_weak() && sym.is_undef() {
        debug_assert_eq!(sym.st_value(), 0);
        Some(SymDef::new(None, source))
    } else {
        None
    }
}

pub(crate) fn find_symdef_impl<
    'lib,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch> + 'static,
    Source,
>(
    source: &'lib Source,
    scope: &'lib ModuleScope<Arch, Tls>,
    sym: &'lib ElfSymbol<Arch::Layout>,
    syminfo: &SymbolInfo,
    symbolic: bool,
) -> Option<SymDef<'lib, Arch, Tls>>
where
    Source: Module<Arch, Tls>,
{
    if unlikely(sym.is_local()) {
        return Some(SymDef::new(Some(sym), source));
    }

    let self_def = || (!sym.is_undef()).then(|| SymDef::new(Some(sym), source));
    let scope_def = || {
        let mut lookup = SymbolLookup::from_info(syminfo.clone());
        scope.iter().find_map(|scope_source| {
            scope_source.exports().lookup(&mut lookup).map(|sym| {
                logging::trace!(
                    "binding file [{}] to [{}]: symbol [{}]",
                    source.name(),
                    scope_source.name(),
                    syminfo.name()
                );
                SymDef::new(Some(sym), &**scope_source)
            })
        })
    };

    if symbolic {
        self_def().or_else(scope_def)
    } else {
        scope_def().or_else(self_def)
    }
    .or_else(|| weak_undef(source, sym))
}
