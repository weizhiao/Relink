use super::resolve_ifunc;
use crate::{
    Error, RelocReason, Result,
    elf::{ElfHashTable, ElfRelEntry, ElfRelType, ElfSymbol, ElfSymbolType, HashTable, SymbolInfo},
    image::{ElfCore, Module, ModuleScope},
    logging,
    observer::{IfuncBindingEvent, RelocationObserver, SymbolBindingEvent},
    os::{RegionAccess, VmAddr, VmOffset},
    relocate_context_error,
    relocation::{HandleResult, RelocationArch, RelocationContext, RelocationHandler},
    tls::{TlsDescArgs, lookup_tls_get_addr},
};
use core::marker::PhantomData;

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<
    'find,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    PreH: ?Sized,
    PostH: ?Sized,
    Obs: ?Sized,
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    pub(crate) core: &'find ElfCore<D, Arch, R, H>,
    pub(crate) scope: ModuleScope<Arch>,
    pub(crate) pre_handler: &'find PreH,
    pub(crate) post_handler: &'find PostH,
    pub(crate) observer: &'find mut Obs,
    #[allow(dead_code)]
    pub(crate) tls_get_addr: VmAddr,
    pub(crate) tls_desc_args: TlsDescArgs,
}

impl<'find, D, Arch, R, PreH, PostH, Obs, H> RelocHelper<'find, D, Arch, R, PreH, PostH, Obs, H>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    H: ElfHashTable<Arch::Layout> + 'static,
    PreH: RelocationHandler<Arch> + ?Sized,
    PostH: RelocationHandler<Arch> + ?Sized,
    Obs: RelocationObserver<Arch> + ?Sized,
{
    pub(crate) fn new(
        core: &'find ElfCore<D, Arch, R, H>,
        scope: ModuleScope<Arch>,
        pre_handler: &'find PreH,
        post_handler: &'find PostH,
        observer: &'find mut Obs,
        tls_get_addr: VmAddr,
    ) -> Self {
        Self {
            core,
            scope,
            pre_handler,
            post_handler,
            observer,
            tls_get_addr,
            tls_desc_args: TlsDescArgs::default(),
        }
    }

    #[inline]
    pub(crate) fn handle_pre(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let hctx = RelocationContext::new(rel, self.core, &self.scope);
        self.pre_handler.handle(&hctx)
    }

    #[inline]
    pub(crate) fn handle_post(&mut self, rel: &ElfRelType<Arch>) -> Result<HandleResult> {
        let hctx = RelocationContext::new(rel, self.core, &self.scope);
        self.post_handler.handle(&hctx)
    }

    #[inline]
    pub(crate) fn find_symbol(&mut self, rel: &ElfRelType<Arch>) -> Result<Option<VmAddr>> {
        let (dynsym, syminfo) = self.core.symtab().symbol_idx(rel.r_symbol());
        let resolved =
            find_symbol_addr(self.core, &self.scope, dynsym, &syminfo, self.tls_get_addr);
        let mut event = SymbolBindingEvent::new(self.core, rel, dynsym, syminfo.name(), resolved);
        self.observer.on_symbol_binding(&mut event)?;
        Ok(event.into_resolved_addr())
    }

    #[inline]
    pub(crate) fn find_symdef(&mut self, r_sym: usize) -> Option<SymDef<'_, D, Arch>> {
        let (dynsym, syminfo) = self.core.symtab().symbol_idx(r_sym);
        find_symdef_impl(self.core, &self.scope, dynsym, &syminfo)
    }

    #[inline]
    pub(crate) fn resolve_ifunc(
        &mut self,
        rel: &ElfRelType<Arch>,
        resolver: VmAddr,
    ) -> Result<VmAddr> {
        let mut event = IfuncBindingEvent::new(self.core, rel, resolver);
        self.observer.on_ifunc_binding(&mut event)?;
        if let Some(resolved) = event.into_resolved_addr() {
            return Ok(resolved);
        }
        if !Arch::SUPPORTS_NATIVE_RUNTIME {
            return Err(reloc_error(rel, RelocReason::UnknownSymbol, self.core));
        }
        let ptr = self
            .core
            .host_ptr(resolver)
            .expect("IFUNC resolver address is not backed by host-accessible mapped memory");
        Ok(unsafe { resolve_ifunc(ptr) })
    }
}

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub struct SymDef<'lib, D: 'static, Arch: RelocationArch> {
    pub(crate) sym: Option<&'lib ElfSymbol<Arch::Layout>>,
    pub(crate) source: &'lib dyn Module<Arch>,
    _marker: PhantomData<fn() -> D>,
}

impl<'lib, D: 'static, Arch: RelocationArch> SymDef<'lib, D, Arch> {
    #[inline]
    pub(crate) fn new(
        sym: Option<&'lib ElfSymbol<Arch::Layout>>,
        source: &'lib dyn Module<Arch>,
    ) -> Self {
        Self {
            sym,
            source,
            _marker: PhantomData,
        }
    }

    /// Computes the real address of the symbol (base + st_value).
    ///
    /// For regular symbols, returns base + st_value.
    /// For IFUNC symbols, calls the resolver function and returns its result.
    /// For undefined weak symbols, returns null.
    pub(crate) fn convert(self) -> VmAddr {
        if likely(self.sym.is_some()) {
            let base = self.source.base();
            let sym = unsafe { self.sym.unwrap_unchecked() };
            let addr = base + VmOffset::new(sym.st_value());
            if likely(
                sym.symbol_type() != ElfSymbolType::GNU_IFUNC || !Arch::SUPPORTS_NATIVE_RUNTIME,
            ) {
                addr
            } else {
                let ptr = self.source.host_ptr(addr).expect(
                    "IFUNC resolver address is not backed by host-accessible mapped memory",
                );
                unsafe { resolve_ifunc(ptr) }
            }
        } else {
            // 未定义的弱符号返回null
            VmAddr::null()
        }
    }

    #[inline]
    pub fn symbol(&self) -> Option<&'lib ElfSymbol<Arch::Layout>> {
        self.sym
    }

    #[inline]
    pub fn source(&self) -> &'lib dyn Module<Arch> {
        self.source
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls_mod_id(&self) -> Option<crate::tls::TlsModuleId> {
        self.source.tls_mod_id()
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls_tp_offset(&self) -> Option<crate::tls::TlsTpOffset> {
        self.source.tls_tp_offset()
    }

    #[inline]
    pub(crate) fn read_bytes(&self, offset: VmOffset, dst: &mut [u8]) -> Result<()> {
        self.source.read_bytes(offset, dst)
    }
}

/// Creates a detailed relocation error.
///
/// The dynamic parts are stored structurally and formatted only in `Display`.
#[cold]
pub(crate) fn reloc_error<A, D, R, H>(
    rel: &ElfRelType<A>,
    reason: RelocReason,
    lib: &ElfCore<D, A, R, H>,
) -> Error
where
    A: RelocationArch,
    R: RegionAccess,
    H: ElfHashTable<A::Layout> + 'static,
{
    let r_type_str = A::rel_type_to_str(rel.r_type());
    let r_sym = rel.r_symbol();
    if r_sym == 0 {
        relocate_context_error(lib.name(), r_type_str, None, reason)
    } else {
        relocate_context_error(
            lib.name(),
            r_type_str,
            Some(lib.symtab().symbol_idx(r_sym).1.name()),
            reason,
        )
    }
}

fn find_weak<'lib, D, Arch: RelocationArch, R: RegionAccess, H>(
    lib: &'lib ElfCore<D, Arch, R, H>,
    dynsym: &'lib ElfSymbol<Arch::Layout>,
) -> Option<SymDef<'lib, D, Arch>>
where
    D: 'static,
    H: ElfHashTable<Arch::Layout> + 'static,
{
    // 弱符号 + WEAK 用 0 填充rela offset
    if dynsym.is_weak() && dynsym.is_undef() {
        assert!(dynsym.st_value() == 0);
        Some(SymDef::new(None, lib))
    } else if dynsym.st_value() != 0 {
        Some(SymDef::new(Some(dynsym), lib))
    } else {
        None
    }
}

/// Finds the address of a symbol using the configured lookup scope.
///
/// Returns the resolved address.
#[inline]
fn find_symbol_addr<D, Arch, R, H>(
    core: &ElfCore<D, Arch, R, H>,
    scope: &ModuleScope<Arch>,
    dynsym: &ElfSymbol<Arch::Layout>,
    syminfo: &SymbolInfo<'_>,
    tls_get_addr: VmAddr,
) -> Option<VmAddr>
where
    Arch: RelocationArch,
    R: RegionAccess,
    D: 'static,
    H: ElfHashTable<Arch::Layout> + 'static,
{
    if Arch::SUPPORTS_NATIVE_RUNTIME
        && let Some(addr) = lookup_tls_get_addr(syminfo.name(), tls_get_addr)
    {
        logging::trace!(
            "binding file [{}] to [tls_get_addr]: symbol [{}]",
            core.name(),
            syminfo.name()
        );
        return Some(VmAddr::from_ptr(addr));
    }
    if let Some(res) = find_symdef_impl(core, scope, dynsym, &syminfo) {
        return Some(res.convert());
    }
    None
}

pub(crate) fn find_symdef_impl<'lib, D, Arch: RelocationArch, R: RegionAccess, H>(
    core: &'lib ElfCore<D, Arch, R, H>,
    scope: &'lib ModuleScope<Arch>,
    sym: &'lib ElfSymbol<Arch::Layout>,
    syminfo: &SymbolInfo,
) -> Option<SymDef<'lib, D, Arch>>
where
    D: 'static,
    H: ElfHashTable<Arch::Layout> + 'static,
{
    if unlikely(sym.is_local()) {
        Some(SymDef::new(Some(sym), core))
    } else {
        let mut precompute = syminfo.precompute();
        scope
            .iter()
            .find_map(|source| {
                source.lookup_symbol(syminfo, &mut precompute).map(|sym| {
                    logging::trace!(
                        "binding file [{}] to [{}]: symbol [{}]",
                        core.name(),
                        source.name(),
                        syminfo.name()
                    );
                    SymDef::new(Some(sym), &**source)
                })
            })
            .or_else(|| find_weak(core, sym))
    }
}

#[inline]
#[cold]
fn cold() {}

#[inline]
pub(crate) fn likely(b: bool) -> bool {
    if !b {
        cold()
    }
    b
}

#[inline]
pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        cold()
    }
    b
}
