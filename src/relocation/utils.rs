use crate::{
    Error, Result,
    elf::{ElfRelType, ElfSymbol, SymbolInfo, SymbolTable},
    image::{ElfCore, LoadedCore},
    relocate_error,
    relocation::{Relocatable, RelocationContext, RelocationHandler, SymbolLookup},
    sync::Arc,
    tls::TlsDescDynamicArg,
};
use alloc::{boxed::Box, format, string::ToString, vec, vec::Vec};
use core::{
    ops::{Add, Sub},
    ptr::null,
};
use elf::abi::STT_GNU_IFUNC;

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<'find, D, PreS: ?Sized, PostS: ?Sized, PreH: ?Sized, PostH: ?Sized> {
    pub(crate) core: &'find ElfCore<D>,
    pub(crate) scope: Vec<LoadedCore<D>>,
    pub(crate) pre_find: &'find PreS,
    pub(crate) post_find: &'find PostS,
    pub(crate) pre_handler: &'find PreH,
    pub(crate) post_handler: &'find PostH,
    pub(crate) dependency_flags: Vec<bool>,
    pub(crate) tls_get_addr: usize,
    pub(crate) tls_desc_args: Vec<Box<TlsDescDynamicArg>>,
}

impl<'find, D, PreS, PostS, PreH, PostH> RelocHelper<'find, D, PreS, PostS, PreH, PostH>
where
    PreS: SymbolLookup + ?Sized,
    PostS: SymbolLookup + ?Sized,
    PreH: RelocationHandler + ?Sized,
    PostH: RelocationHandler + ?Sized,
{
    pub(crate) fn new(
        core: &'find ElfCore<D>,
        scope: Vec<LoadedCore<D>>,
        pre_find: &'find PreS,
        post_find: &'find PostS,
        pre_handler: &'find PreH,
        post_handler: &'find PostH,
        tls_get_addr: usize,
    ) -> Self {
        let dependency_flags = vec![false; scope.len()];
        Self {
            core,
            scope,
            pre_find,
            post_find,
            pre_handler,
            post_handler,
            dependency_flags,
            tls_get_addr,
            tls_desc_args: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn handle_pre(&mut self, rel: &ElfRelType) -> Result<bool> {
        let hctx = RelocationContext::new(rel, self.core, &self.scope);
        let opt = self.pre_handler.handle(&hctx);
        if let Some(r) = opt {
            if let Some(idx) = r? {
                self.dependency_flags[idx] = true;
            }
            return Ok(false);
        }
        Ok(true)
    }

    #[inline]
    pub(crate) fn handle_post(&mut self, rel: &ElfRelType) -> Result<bool> {
        let hctx = RelocationContext::new(rel, self.core, &self.scope);
        let opt = self.post_handler.handle(&hctx);
        if let Some(r) = opt {
            if let Some(idx) = r? {
                self.dependency_flags[idx] = true;
            }
            return Ok(false);
        }
        Ok(true)
    }

    #[inline]
    pub(crate) fn find_symbol(&mut self, r_sym: usize) -> Option<RelocValue<usize>> {
        let (symbol, idx) = find_symbol_addr(
            self.pre_find,
            self.post_find,
            self.core,
            self.core.symtab(),
            &self.scope,
            r_sym,
        )?;
        if let Some(idx) = idx {
            self.dependency_flags[idx] = true;
        }
        Some(symbol)
    }

    #[inline]
    pub(crate) fn find_symdef(&mut self, r_sym: usize) -> Option<SymDef<'_, D>> {
        let (dynsym, syminfo) = self.core.symtab().symbol_idx(r_sym);
        let (symdef, idx) = find_symdef_impl(self.core, &self.scope, dynsym, &syminfo)?;
        if let Some(idx) = idx {
            self.dependency_flags[idx] = true;
        }
        Some(symdef)
    }

    pub(crate) fn finish(self, needed_libs: &[&str]) -> Vec<LoadedCore<D>> {
        self.scope
            .into_iter()
            .zip(self.dependency_flags)
            .filter_map(|(module, flag)| {
                (flag || needed_libs.contains(&module.short_name())).then(|| module)
            })
            .collect()
    }
}

/// A builder for configuring and executing the relocation process.
///
/// `Relocator` provides a fluent interface for setting up symbol resolution,
/// relocation handlers, and binding behaviors before relocating an ELF object.
///
/// # Examples
/// ```no_run
/// use elf_loader::{Loader, input::ElfBinary};
///
/// let mut loader = Loader::new();
/// let bytes = &[]; // ELF file bytes
/// let lib = loader.load_dylib(ElfBinary::new("liba.so", bytes)).unwrap();
///
/// let relocated = lib.relocator()
///     .pre_find_fn(|name| {
///         match name {
///             "malloc" => Some(0x1234 as *const ()),
///             "free" => Some(0x5678 as *const ()),
///             _ => None,
///         }
///     })
///     .lazy(true)
///     .relocate()
///     .unwrap();
/// ```
pub struct Relocator<T, PreS, PostS, LazyS, PreH, PostH, D = ()> {
    object: T,
    scope: Vec<LoadedCore<D>>,
    pre_find: PreS,
    post_find: PostS,
    pre_handler: PreH,
    post_handler: PostH,
    lazy: Option<bool>,
    lazy_scope: Option<LazyS>,
}

impl<T: Relocatable<D>, D> Relocator<T, (), (), (), (), (), D> {
    /// Creates a new `Relocator` builder for the given object.
    pub fn new(object: T) -> Self {
        Self {
            object,
            scope: Vec::new(),
            pre_find: (),
            post_find: (),
            pre_handler: (),
            post_handler: (),
            lazy: None,
            lazy_scope: None,
        }
    }
}

impl<T, PreS, PostS, LazyS, PreH, PostH, D> Relocator<T, PreS, PostS, LazyS, PreH, PostH, D>
where
    T: Relocatable<D>,
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler,
    PostH: RelocationHandler,
{
    /// Sets the preferred symbol lookup strategy.
    ///
    /// Symbols will be searched using this strategy first, before checking
    /// the default scope or fallback strategies.
    pub fn pre_find<S2>(self, pre_find: S2) -> Relocator<T, S2, PostS, LazyS, PreH, PostH, D>
    where
        S2: SymbolLookup,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find,
            post_find: self.post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            lazy: self.lazy,
            lazy_scope: self.lazy_scope,
        }
    }

    /// Sets the preferred symbol lookup strategy using a closure.
    pub fn pre_find_fn<F>(self, pre_find: F) -> Relocator<T, F, PostS, LazyS, PreH, PostH, D>
    where
        F: Fn(&str) -> Option<*const ()>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find,
            post_find: self.post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            lazy: self.lazy,
            lazy_scope: self.lazy_scope,
        }
    }

    /// Sets the fallback symbol lookup strategy using a closure.
    ///
    /// This strategy will be used if a symbol is not found in the preferred
    /// strategy or the default scope.
    pub fn post_find_fn<F>(self, post_find: F) -> Relocator<T, PreS, F, LazyS, PreH, PostH, D>
    where
        F: Fn(&str) -> Option<*const ()>,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            lazy: self.lazy,
            lazy_scope: self.lazy_scope,
        }
    }

    /// Sets the fallback symbol lookup strategy.
    ///
    /// This strategy will be used if a symbol is not found in the preferred
    /// strategy or the default scope.
    pub fn post_find<S2>(self, post_find: S2) -> Relocator<T, PreS, S2, LazyS, PreH, PostH, D>
    where
        S2: SymbolLookup,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            lazy: self.lazy,
            lazy_scope: self.lazy_scope,
        }
    }

    /// Sets the scope of relocated libraries for symbol resolution.
    ///
    /// The relocator will search for symbols in these libraries in the order
    /// they are provided. This defines the dependency resolution scope.
    pub fn scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: core::borrow::Borrow<LoadedCore<D>>,
    {
        self.scope = scope.into_iter().map(|r| r.borrow().clone()).collect();
        self
    }

    /// Adds more libraries to the search scope.
    ///
    /// This appends libraries to the existing scope. Symbols will be searched
    /// in the order they were added.
    pub fn add_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: core::borrow::Borrow<LoadedCore<D>>,
    {
        self.scope
            .extend(scope.into_iter().map(|r| r.borrow().clone()));
        self
    }

    /// Sets the pre-processing relocation handler.
    ///
    /// This handler is called before the default relocation logic.
    pub fn pre_handler<NewPreH>(
        self,
        handler: NewPreH,
    ) -> Relocator<T, PreS, PostS, LazyS, NewPreH, PostH, D>
    where
        NewPreH: RelocationHandler,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            pre_handler: handler,
            post_handler: self.post_handler,
            lazy: self.lazy,
            lazy_scope: self.lazy_scope,
        }
    }

    /// Sets the post-processing relocation handler.
    ///
    /// This handler is called after the default relocation logic if the
    /// relocation was not already handled.
    pub fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> Relocator<T, PreS, PostS, LazyS, PreH, NewPostH, D>
    where
        NewPostH: RelocationHandler,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            pre_handler: self.pre_handler,
            post_handler: handler,
            lazy: self.lazy,
            lazy_scope: self.lazy_scope,
        }
    }

    /// Enables or disables lazy binding.
    ///
    /// When enabled, some relocations (typically PLT entries) will be resolved
    /// on-demand when the function is first called, improving startup time.
    /// When disabled, all relocations are resolved immediately.
    pub fn lazy(mut self, lazy: bool) -> Self {
        self.lazy = Some(lazy);
        self
    }

    /// Sets the lazy scope for symbol resolution during lazy binding.
    pub fn lazy_scope<NewLazyS>(
        self,
        scope: NewLazyS,
    ) -> Relocator<T, PreS, PostS, NewLazyS, PreH, PostH, D>
    where
        NewLazyS: SymbolLookup + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            lazy: self.lazy,
            lazy_scope: Some(scope),
        }
    }

    /// Executes the relocation process.
    ///
    /// This method consumes the relocator and returns the relocated ELF object.
    /// All configured symbol lookups, handlers, and options are applied.
    ///
    /// # Returns
    /// * `Ok(T::Output)` - The successfully relocated ELF object.
    /// * `Err(Error)` - If relocation fails for any reason.
    pub fn relocate(self) -> Result<T::Output>
    where
        D: 'static,
    {
        self.object.relocate(
            self.scope,
            &self.pre_find,
            &self.post_find,
            &self.pre_handler,
            &self.post_handler,
            self.lazy,
            self.lazy_scope,
        )
    }
}

/// A wrapper type for relocation values, providing type safety and arithmetic operations.
///
/// This type represents computed addresses or offsets used in relocations.
/// It supports addition and subtraction for address calculations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct RelocValue<T>(pub T);

impl<T> RelocValue<T> {
    #[inline]
    pub const fn new(val: T) -> Self {
        Self(val)
    }
}

impl RelocValue<usize> {
    #[inline]
    #[allow(dead_code)]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

impl Add<usize> for RelocValue<usize> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: usize) -> Self::Output {
        RelocValue(self.0.wrapping_add(rhs))
    }
}

impl Add<isize> for RelocValue<usize> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: isize) -> Self::Output {
        RelocValue(self.0.wrapping_add_signed(rhs))
    }
}

impl Sub<usize> for RelocValue<usize> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: usize) -> Self::Output {
        RelocValue(self.0.wrapping_sub(rhs))
    }
}

impl From<usize> for RelocValue<usize> {
    #[inline]
    fn from(val: usize) -> Self {
        Self(val)
    }
}

impl From<RelocValue<usize>> for usize {
    #[inline]
    fn from(value: RelocValue<usize>) -> Self {
        value.0
    }
}

impl TryFrom<RelocValue<usize>> for RelocValue<i32> {
    type Error = crate::Error;

    #[inline]
    fn try_from(value: RelocValue<usize>) -> Result<Self> {
        i32::try_from(value.0 as isize)
            .map(RelocValue)
            .map_err(|err| relocate_error(err.to_string()))
    }
}

impl TryFrom<RelocValue<usize>> for RelocValue<u32> {
    type Error = crate::Error;

    #[inline]
    fn try_from(value: RelocValue<usize>) -> Result<Self> {
        u32::try_from(value.0)
            .map(RelocValue)
            .map_err(|err| relocate_error(err.to_string()))
    }
}

/// A symbol definition found during relocation.
///
/// Contains the symbol information and the module where it was found.
/// Used to compute the final address of a symbol.
pub struct SymDef<'lib, D> {
    pub sym: Option<&'lib ElfSymbol>,
    pub lib: &'lib ElfCore<D>,
}

impl<'temp, D> SymDef<'temp, D> {
    /// Computes the real address of the symbol (base + st_value).
    ///
    /// For regular symbols, returns base + st_value.
    /// For IFUNC symbols, calls the resolver function and returns its result.
    /// For undefined weak symbols, returns null.
    pub fn convert(self) -> *const () {
        if likely(self.sym.is_some()) {
            let base = self.lib.base();
            let sym = unsafe { self.sym.unwrap_unchecked() };
            let addr = base + sym.st_value();
            if likely(sym.st_type() != STT_GNU_IFUNC) {
                addr as _
            } else {
                // IFUNC会在运行时确定地址，这里使用的是ifunc的返回值
                let ifunc: fn() -> usize = unsafe { core::mem::transmute(addr) };
                ifunc() as _
            }
        } else {
            // 未定义的弱符号返回null
            null()
        }
    }
}

/// Creates a detailed relocation error message.
///
/// Formats an error with relocation type, symbol name (if any), and module information.
#[cold]
pub(crate) fn reloc_error<D, E: core::fmt::Display>(
    rel: &ElfRelType,
    err: E,
    lib: &ElfCore<D>,
) -> Error {
    let r_type_str = rel.r_type_str();
    let r_sym = rel.r_symbol();
    if r_sym == 0 {
        relocate_error(format!(
            "file: {}, relocation type: {}, no symbol, error: {}",
            lib.name(),
            r_type_str,
            err
        ))
    } else {
        relocate_error(format!(
            "file: {}, relocation type: {}, symbol name: {}, error: {}",
            lib.name(),
            r_type_str,
            lib.symtab().symbol_idx(r_sym).1.name(),
            err
        ))
    }
}

fn find_weak<'lib, D>(lib: &'lib ElfCore<D>, dynsym: &'lib ElfSymbol) -> Option<SymDef<'lib, D>> {
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
/// Returns the resolved address and optionally the library index used.
#[inline]
pub(crate) fn find_symbol_addr<PreS, PostS, D>(
    pre_find: &PreS,
    post_find: &PostS,
    core: &ElfCore<D>,
    symtab: &SymbolTable,
    scope: &[LoadedCore<D>],
    r_sym: usize,
) -> Option<(RelocValue<usize>, Option<usize>)>
where
    PreS: SymbolLookup + ?Sized,
    PostS: SymbolLookup + ?Sized,
{
    let (dynsym, syminfo) = symtab.symbol_idx(r_sym);
    if let Some(addr) = pre_find.lookup(syminfo.name()) {
        #[cfg(feature = "log")]
        log::trace!(
            "binding file [{}] to [pre_find]: symbol [{}]",
            core.name(),
            syminfo.name()
        );
        return Some((RelocValue::new(addr as usize), None));
    }
    if let Some(res) = find_symdef_impl(core, scope, dynsym, &syminfo) {
        return Some((RelocValue::new(res.0.convert() as usize), res.1));
    }
    if let Some(addr) = post_find.lookup(syminfo.name()) {
        #[cfg(feature = "log")]
        log::trace!(
            "binding file [{}] to [post_find]: symbol [{}]",
            core.name(),
            syminfo.name()
        );
        return Some((RelocValue::new(addr as usize), None));
    }
    None
}

pub(crate) fn find_symdef_impl<'lib, D>(
    core: &'lib ElfCore<D>,
    scope: &'lib [LoadedCore<D>],
    sym: &'lib ElfSymbol,
    syminfo: &SymbolInfo,
) -> Option<(SymDef<'lib, D>, Option<usize>)> {
    if unlikely(sym.is_local()) {
        Some((
            SymDef {
                sym: Some(sym),
                lib: core,
            },
            None,
        ))
    } else {
        let mut precompute = syminfo.precompute();
        scope
            .iter()
            .enumerate()
            .find_map(|(i, lib)| {
                lib.symtab()
                    .lookup_filter(syminfo, &mut precompute)
                    .map(|sym| {
                        #[cfg(feature = "log")]
                        log::trace!(
                            "binding file [{}] to [{}]: symbol [{}]",
                            core.name(),
                            lib.name(),
                            syminfo.name()
                        );
                        // 如果找到的库和当前 core 指向同一个 ELF（同一 allocation），
                        // 不返回库索引，避免增加引用或产生生命周期循环导致内存泄漏。
                        let same = Arc::as_ptr(&lib.core.inner) == Arc::as_ptr(&core.inner);
                        (
                            SymDef {
                                sym: Some(sym),
                                lib: &lib.core,
                            },
                            if same { None } else { Some(i) },
                        )
                    })
            })
            .or_else(|| find_weak(core, sym).map(|s| (s, None)))
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
