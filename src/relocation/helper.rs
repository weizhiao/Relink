use crate::{
    Error, RelocReason, Result,
    elf::{
        ElfRelEntry, ElfRelType, ElfSymbol, ElfSymbolType, HashTable, SymbolInfo, SymbolTableView,
    },
    hint::{likely, unlikely},
    image::{ElfCore, Module, ModuleScope},
    logging,
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    observer::{RelocationObserver, SymbolBindingEvent},
    relocate_context_error,
    relocation::{HandleResult, RelocationArch, RelocationContext, RelocationHandler},
    runtime::{CodeContext, CodeExecutor},
    segment::ElfSegments,
    tls::{TLS_GET_ADDR_SYMBOL, TlsDescArgs, TlsResolver},
};

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<
    'find,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver + 'static,
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
    pub(crate) tls_desc_args: TlsDescArgs,
}

impl<'find, D, Arch, R, Tls, PreH, PostH, Obs, H, Memory>
    RelocHelper<'find, D, Arch, R, Tls, PreH, PostH, Obs, H, Memory>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver,
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
            tls_desc_args: TlsDescArgs::default(),
        }
    }

    #[inline]
    pub(crate) fn memory(&self) -> &Memory {
        &self.memory
    }

    #[inline]
    pub(crate) fn symbols(&self) -> SymbolTableView<'find, Arch::Layout, H> {
        self.symbols
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

    #[inline]
    pub(crate) fn find_symbol(&mut self, rel: &ElfRelType<Arch>) -> Result<Option<VmAddr>> {
        let (dynsym, syminfo) = self.symbols.symbol_idx(rel.r_symbol());
        let resolved = if let Some(addr) = self.find_runtime_symbol(&syminfo) {
            Some(addr)
        } else if let Some(symdef) = find_symdef_impl(
            self.core,
            &self.scope,
            dynsym,
            &syminfo,
            self.core.symbolic(),
        ) {
            Some(symdef.resolve_addr(self.executor)?)
        } else {
            None
        };
        let mut event =
            SymbolBindingEvent::new(self.core, Some(rel), dynsym, syminfo.name(), resolved);
        self.observer.on_symbol_binding(&mut event)?;
        Ok(event.into_resolved_addr())
    }

    #[inline]
    fn find_runtime_symbol(&self, syminfo: &SymbolInfo<'_>) -> Option<VmAddr> {
        if Tls::OVERRIDE_TLS_GET_ADDR && syminfo.name() == TLS_GET_ADDR_SYMBOL {
            self.core.tls_get_addr()
        } else {
            None
        }
    }

    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn symbol_addr(&self, r_sym: usize) -> VmAddr {
        let (symbol, _) = self.symbols.symbol_idx(r_sym);
        self.core.base() + VmOffset::new(symbol.st_value())
    }

    #[inline]
    pub(crate) fn find_symdef(&mut self, r_sym: usize) -> Option<SymDef<'_, Arch, Tls>> {
        let (dynsym, syminfo) = self.symbols.symbol_idx(r_sym);
        find_symdef_impl(
            self.core,
            &self.scope,
            dynsym,
            &syminfo,
            self.core.symbolic(),
        )
    }
}

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub struct SymDef<'lib, Arch: RelocationArch, Tls: TlsResolver = ()> {
    pub(crate) sym: Option<&'lib ElfSymbol<Arch::Layout>>,
    pub(crate) source: &'lib dyn Module<Arch, Tls>,
}

impl<'lib, Arch: RelocationArch, Tls: TlsResolver + 'static> SymDef<'lib, Arch, Tls> {
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

/// Creates a detailed relocation error.
///
/// The dynamic parts are stored structurally and formatted only in `Display`.
#[cold]
pub(crate) fn reloc_error<A, D, R, Tls, H>(
    rel: &ElfRelType<A>,
    reason: RelocReason,
    lib: &ElfCore<D, A, R, Tls>,
    symbols: SymbolTableView<'_, A::Layout, H>,
) -> Error
where
    A: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver,
{
    let r_type_str = A::rel_type_to_str(rel.r_type());
    let r_sym = rel.r_symbol();
    if r_sym == 0 {
        relocate_context_error(lib.name(), r_type_str, None, reason)
    } else {
        relocate_context_error(
            lib.name(),
            r_type_str,
            Some(symbols.symbol_idx(r_sym).1.name()),
            reason,
        )
    }
}

#[cold]
fn weak_undef<'lib, Arch, Tls, Source>(
    source: &'lib Source,
    sym: &'lib ElfSymbol<Arch::Layout>,
) -> Option<SymDef<'lib, Arch, Tls>>
where
    Arch: RelocationArch,
    Tls: TlsResolver + 'static,
    Source: Module<Arch, Tls>,
{
    if sym.is_weak() && sym.is_undef() {
        debug_assert_eq!(sym.st_value(), 0);
        Some(SymDef::new(None, source))
    } else {
        None
    }
}

pub(crate) fn find_symdef_impl<'lib, Arch: RelocationArch, Tls: TlsResolver + 'static, Source>(
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
        let mut precompute = syminfo.precompute();
        scope.iter().find_map(|scope_source| {
            scope_source
                .exports()
                .lookup(syminfo, &mut precompute)
                .map(|sym| {
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
