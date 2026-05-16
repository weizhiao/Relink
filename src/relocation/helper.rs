use super::{RelocAddr, resolve_ifunc};
use crate::relocation::{TlsDescEmuRequest, TlsDescEmuValue};
use crate::{
    Error, RelocReason, Result,
    elf::{ElfRelEntry, ElfRelType, ElfSymbol, ElfSymbolType, SymbolInfo, SymbolTable},
    image::{ElfCore, Module, ModuleScope},
    logging, relocate_context_error,
    relocation::{
        EmuRelocationContext, Emulator, HandleResult, RelocationArch, RelocationContext,
        RelocationHandler,
    },
    sync::Arc,
    tls::{TlsDescArgs, lookup_tls_get_addr},
};
use core::marker::PhantomData;

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<'find, D: 'static, Arch: RelocationArch, PreH: ?Sized, PostH: ?Sized>
{
    pub(crate) core: &'find ElfCore<D, Arch>,
    pub(crate) scope: ModuleScope<Arch>,
    pub(crate) pre_handler: &'find PreH,
    pub(crate) post_handler: &'find PostH,
    #[allow(dead_code)]
    pub(crate) tls_get_addr: RelocAddr,
    pub(crate) tls_desc_args: TlsDescArgs,
    pub(crate) emu: Option<Arc<dyn Emulator<Arch>>>,
}

impl<'find, D, Arch, PreH, PostH> RelocHelper<'find, D, Arch, PreH, PostH>
where
    D: 'static,
    Arch: RelocationArch,
    PreH: RelocationHandler<Arch> + ?Sized,
    PostH: RelocationHandler<Arch> + ?Sized,
{
    pub(crate) fn new(
        core: &'find ElfCore<D, Arch>,
        scope: ModuleScope<Arch>,
        pre_handler: &'find PreH,
        post_handler: &'find PostH,
        tls_get_addr: RelocAddr,
        emu: Option<Arc<dyn Emulator<Arch>>>,
    ) -> Self {
        Self {
            core,
            scope,
            pre_handler,
            post_handler,
            tls_get_addr,
            tls_desc_args: TlsDescArgs::default(),
            emu,
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
    pub(crate) fn find_symbol(&mut self, r_sym: usize) -> Option<RelocAddr> {
        find_symbol_addr(
            self.core,
            self.core.symtab(),
            &self.scope,
            r_sym,
            self.tls_get_addr,
        )
    }

    #[inline]
    pub(crate) fn find_symdef(&mut self, r_sym: usize) -> Option<SymDef<'_, D, Arch>> {
        let (dynsym, syminfo) = self.core.symtab().symbol_idx(r_sym);
        find_symdef_impl(self.core, &self.scope, dynsym, &syminfo)
    }

    #[inline]
    pub(crate) fn resolve_ifunc_with_emu(
        &self,
        rel: &ElfRelType<Arch>,
        resolver: RelocAddr,
    ) -> Result<Option<RelocAddr>> {
        let Some(emu) = &self.emu else {
            return Ok(None);
        };
        let ctx = EmuRelocationContext::new(self.core, rel);
        emu.resolve_ifunc(&ctx, resolver.into_inner())
            .map(RelocAddr::new)
            .map(Some)
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn resolve_tlsdesc_with_emu(
        &self,
        rel: &ElfRelType<Arch>,
        request: TlsDescEmuRequest,
    ) -> Result<Option<TlsDescEmuValue>> {
        let Some(emu) = &self.emu else {
            return Ok(None);
        };
        let ctx = EmuRelocationContext::new(self.core, rel);
        emu.resolve_tlsdesc(&ctx, request).map(Some)
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
    pub(crate) fn convert(self) -> RelocAddr {
        if likely(self.sym.is_some()) {
            let base = RelocAddr::new(self.source.base_addr());
            let sym = unsafe { self.sym.unwrap_unchecked() };
            let addr = base.offset(sym.st_value());
            if likely(
                sym.symbol_type() != ElfSymbolType::GNU_IFUNC || !Arch::SUPPORTS_NATIVE_RUNTIME,
            ) {
                addr
            } else {
                unsafe { resolve_ifunc(addr) }
            }
        } else {
            // 未定义的弱符号返回null
            RelocAddr::null()
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
    pub(crate) fn segment_slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        self.source.segment_slice(offset, len)
    }
}

/// Creates a detailed relocation error.
///
/// The dynamic parts are stored structurally and formatted only in `Display`.
#[cold]
pub(crate) fn reloc_error<A, D>(
    rel: &ElfRelType<A>,
    reason: RelocReason,
    lib: &ElfCore<D, A>,
) -> Error
where
    A: RelocationArch,
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

fn find_weak<'lib, D, Arch: RelocationArch>(
    lib: &'lib ElfCore<D, Arch>,
    dynsym: &'lib ElfSymbol<Arch::Layout>,
) -> Option<SymDef<'lib, D, Arch>>
where
    D: 'static,
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
fn find_symbol_addr<D, Arch>(
    core: &ElfCore<D, Arch>,
    symtab: &SymbolTable<Arch::Layout>,
    scope: &ModuleScope<Arch>,
    r_sym: usize,
    tls_get_addr: RelocAddr,
) -> Option<RelocAddr>
where
    Arch: RelocationArch,
    D: 'static,
{
    let (dynsym, syminfo) = symtab.symbol_idx(r_sym);
    if Arch::SUPPORTS_NATIVE_RUNTIME
        && let Some(addr) = lookup_tls_get_addr(syminfo.name(), tls_get_addr)
    {
        logging::trace!(
            "binding file [{}] to [tls_get_addr]: symbol [{}]",
            core.name(),
            syminfo.name()
        );
        return Some(RelocAddr::from_ptr(addr));
    }
    if let Some(res) = find_symdef_impl(core, scope, dynsym, &syminfo) {
        return Some(res.convert());
    }
    None
}

pub(crate) fn find_symdef_impl<'lib, D, Arch: RelocationArch>(
    core: &'lib ElfCore<D, Arch>,
    scope: &'lib ModuleScope<Arch>,
    sym: &'lib ElfSymbol<Arch::Layout>,
    syminfo: &SymbolInfo,
) -> Option<SymDef<'lib, D, Arch>>
where
    D: 'static,
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
