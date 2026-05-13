use super::{RelocAddr, resolve_ifunc};
use crate::{
    Error, RelocationFailureReason, Result,
    elf::{ElfRelEntry, ElfRelType, ElfSymbol, ElfSymbolType, SymbolInfo, SymbolTable},
    image::{ElfCore, LoadedCore},
    logging, relocate_context_error,
    relocation::{
        HandleResult, RelocationArch, RelocationContext, RelocationHandler, SymbolLookup,
    },
    sync::Arc,
    tls::TlsDescArgs,
};

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<
    'find,
    D: 'static,
    Arch: RelocationArch,
    PreS: ?Sized,
    PostS: ?Sized,
    PreH: ?Sized,
    PostH: ?Sized,
> {
    pub(crate) core: &'find ElfCore<D, Arch>,
    pub(crate) scope: Arc<[LoadedCore<D, Arch>]>,
    pub(crate) pre_find: &'find PreS,
    pub(crate) post_find: &'find PostS,
    pub(crate) pre_handler: &'find PreH,
    pub(crate) post_handler: &'find PostH,
    #[allow(dead_code)]
    pub(crate) tls_get_addr: RelocAddr,
    pub(crate) tls_desc_args: TlsDescArgs,
}

impl<'find, D, Arch, PreS, PostS, PreH, PostH> RelocHelper<'find, D, Arch, PreS, PostS, PreH, PostH>
where
    D: 'static,
    Arch: RelocationArch,
    PreS: SymbolLookup + ?Sized,
    PostS: SymbolLookup + ?Sized,
    PreH: RelocationHandler<Arch> + ?Sized,
    PostH: RelocationHandler<Arch> + ?Sized,
{
    pub(crate) fn new(
        core: &'find ElfCore<D, Arch>,
        scope: Arc<[LoadedCore<D, Arch>]>,
        pre_find: &'find PreS,
        post_find: &'find PostS,
        pre_handler: &'find PreH,
        post_handler: &'find PostH,
        tls_get_addr: RelocAddr,
    ) -> Self {
        Self {
            core,
            scope,
            pre_find,
            post_find,
            pre_handler,
            post_handler,
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
    pub(crate) fn find_symbol(&mut self, r_sym: usize) -> Option<RelocAddr> {
        find_symbol_addr(
            self.pre_find,
            self.post_find,
            self.core,
            self.core.symtab(),
            &self.scope,
            r_sym,
        )
    }

    #[inline]
    pub(crate) fn find_symdef(&mut self, r_sym: usize) -> Option<SymDef<'_, D, Arch>> {
        let (dynsym, syminfo) = self.core.symtab().symbol_idx(r_sym);
        find_symdef_impl(self.core, &self.scope, dynsym, &syminfo)
    }
}

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub struct SymDef<'lib, D: 'static, Arch: RelocationArch> {
    pub(crate) sym: Option<&'lib ElfSymbol<Arch::Layout>>,
    pub(crate) lib: &'lib ElfCore<D, Arch>,
}

impl<'lib, D: 'static, Arch: RelocationArch> SymDef<'lib, D, Arch> {
    /// Computes the real address of the symbol (base + st_value).
    ///
    /// For regular symbols, returns base + st_value.
    /// For IFUNC symbols, calls the resolver function and returns its result.
    /// For undefined weak symbols, returns null.
    pub(crate) fn convert(self) -> RelocAddr {
        if likely(self.sym.is_some()) {
            let base = self.lib.base_addr();
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
    pub fn lib(&self) -> &'lib ElfCore<D, Arch> {
        self.lib
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls_mod_id(&self) -> Option<crate::tls::TlsModuleId> {
        self.lib.tls_mod_id()
    }

    #[inline]
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls_tp_offset(&self) -> Option<crate::tls::TlsTpOffset> {
        self.lib.tls_tp_offset()
    }

    #[inline]
    pub(crate) fn segment_slice(&self, offset: usize, len: usize) -> &[u8] {
        self.lib.segment_slice(offset, len)
    }
}

/// Creates a detailed relocation error.
///
/// The dynamic parts are stored structurally and formatted only in `Display`.
#[cold]
pub(crate) fn reloc_error<A, D>(
    rel: &ElfRelType<A>,
    reason: RelocationFailureReason,
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
        Some(SymDef { sym: None, lib })
    } else if dynsym.st_value() != 0 {
        Some(SymDef {
            sym: Some(dynsym),
            lib,
        })
    } else {
        None
    }
}

/// Finds the address of a symbol using the configured lookup strategies.
///
/// Searches in order: pre_find, scope, post_find.
/// Returns the resolved address.
#[inline]
fn find_symbol_addr<PreS, PostS, D, Arch>(
    pre_find: &PreS,
    post_find: &PostS,
    core: &ElfCore<D, Arch>,
    symtab: &SymbolTable<Arch::Layout>,
    scope: &[LoadedCore<D, Arch>],
    r_sym: usize,
) -> Option<RelocAddr>
where
    Arch: RelocationArch,
    D: 'static,
    PreS: SymbolLookup + ?Sized,
    PostS: SymbolLookup + ?Sized,
{
    let (dynsym, syminfo) = symtab.symbol_idx(r_sym);
    if let Some(addr) = pre_find.lookup(syminfo.name()) {
        logging::trace!(
            "binding file [{}] to [pre_find]: symbol [{}]",
            core.name(),
            syminfo.name()
        );
        return Some(RelocAddr::from_ptr(addr));
    }
    if let Some(res) = find_symdef_impl(core, scope, dynsym, &syminfo) {
        return Some(res.convert());
    }
    if let Some(addr) = post_find.lookup(syminfo.name()) {
        logging::trace!(
            "binding file [{}] to [post_find]: symbol [{}]",
            core.name(),
            syminfo.name()
        );
        return Some(RelocAddr::from_ptr(addr));
    }
    None
}

pub(crate) fn find_symdef_impl<'lib, D, Arch: RelocationArch>(
    core: &'lib ElfCore<D, Arch>,
    scope: &'lib [LoadedCore<D, Arch>],
    sym: &'lib ElfSymbol<Arch::Layout>,
    syminfo: &SymbolInfo,
) -> Option<SymDef<'lib, D, Arch>>
where
    D: 'static,
{
    if unlikely(sym.is_local()) {
        Some(SymDef {
            sym: Some(sym),
            lib: core,
        })
    } else {
        let mut precompute = syminfo.precompute();
        scope
            .iter()
            .find_map(|module| {
                module
                    .core
                    .symtab()
                    .lookup_filter(syminfo, &mut precompute)
                    .map(|sym| {
                        logging::trace!(
                            "binding file [{}] to [{}]: symbol [{}]",
                            core.name(),
                            module.name(),
                            syminfo.name()
                        );
                        SymDef {
                            sym: Some(sym),
                            lib: &module.core,
                        }
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
