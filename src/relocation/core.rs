use crate::{
    Error, RelocationError, RelocationFailureReason, Result,
    elf::{ElfRelType, ElfSymbol, ElfSymbolType, SymbolInfo, SymbolTable},
    image::{ElfCore, LoadedCore},
    logging, relocate_context_error,
    relocation::{
        BindingMode, HandleResult, HandlerHooks, LazyLookupHooks, LookupHooks, Relocatable,
        RelocateArgs, RelocationArch, RelocationContext, RelocationHandler, SupportLazy,
        SymbolLookup,
    },
    sync::Arc,
    tls::TlsDescArgs,
};
use alloc::vec::Vec;
use core::ptr::null;

/// Internal context for managing relocation state and handlers.
pub(crate) struct RelocHelper<'find, D, PreS: ?Sized, PostS: ?Sized, PreH: ?Sized, PostH: ?Sized> {
    pub(crate) core: &'find ElfCore<D>,
    pub(crate) scope: Arc<[LoadedCore<D>]>,
    pub(crate) pre_find: &'find PreS,
    pub(crate) post_find: &'find PostS,
    pub(crate) pre_handler: &'find PreH,
    pub(crate) post_handler: &'find PostH,
    #[allow(dead_code)]
    pub(crate) tls_get_addr: RelocAddr,
    pub(crate) tls_desc_args: TlsDescArgs,
}

fn empty_scope<D>() -> Arc<[LoadedCore<D>]> {
    Arc::from(Vec::new())
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
        scope: Arc<[LoadedCore<D>]>,
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
    pub(crate) fn handle_pre(&mut self, rel: &ElfRelType) -> Result<HandleResult> {
        let hctx = RelocationContext::new(rel, self.core, &self.scope);
        self.pre_handler.handle(&hctx)
    }

    #[inline]
    pub(crate) fn handle_post(&mut self, rel: &ElfRelType) -> Result<HandleResult> {
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
    pub(crate) fn find_symdef(&mut self, r_sym: usize) -> Option<SymDef<'_, D>> {
        let (dynsym, syminfo) = self.core.symtab().symbol_idx(r_sym);
        find_symdef_impl(self.core, &self.scope, dynsym, &syminfo)
    }
}

/// A builder for configuring and executing relocation.
///
/// A relocator is obtained by calling `.relocator()` on a raw image returned by
/// [`crate::Loader`]. It lets you provide symbol lookup callbacks, dependency scope,
/// relocation handlers, and binding policy before finally calling `relocate()`.
///
/// # Examples
/// ```no_run
/// use elf_loader::{Loader, Result};
///
/// fn main() -> Result<()> {
///     let mut loader = Loader::new();
///     let lib = loader.load_dylib("path/to/liba.so")?;
///
///     let relocated = lib
///         .relocator()
///         .pre_find_fn(|name| match name {
///             "malloc" => Some(0x1234 as *const ()),
///             "free" => Some(0x5678 as *const ()),
///             _ => None,
///         })
///         .relocate()?;
///
///     let _ = relocated;
///     Ok(())
/// }
/// ```
pub struct Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D = ()> {
    object: T,
    scope: Arc<[LoadedCore<D>]>,
    pre_find: PreS,
    post_find: PostS,
    lazy_pre_find: LazyPreS,
    lazy_post_find: LazyPostS,
    pre_handler: PreH,
    post_handler: PostH,
    binding: BindingMode,
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D> Clone
    for Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
where
    T: Clone,
    PreS: Clone,
    PostS: Clone,
    LazyPreS: Clone,
    LazyPostS: Clone,
    PreH: Clone,
    PostH: Clone,
{
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            scope: self.scope.clone(),
            pre_find: self.pre_find.clone(),
            post_find: self.post_find.clone(),
            lazy_pre_find: self.lazy_pre_find.clone(),
            lazy_post_find: self.lazy_post_find.clone(),
            pre_handler: self.pre_handler.clone(),
            post_handler: self.post_handler.clone(),
            binding: self.binding,
        }
    }
}

impl Relocator<(), (), (), (), (), (), (), ()> {
    /// Creates a new empty `Relocator` configuration.
    pub fn new() -> Self {
        Self {
            object: (),
            scope: empty_scope(),
            pre_find: (),
            post_find: (),
            lazy_pre_find: (),
            lazy_post_find: (),
            pre_handler: (),
            post_handler: (),
            binding: BindingMode::Default,
        }
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
where
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyPreS: SymbolLookup + Send + Sync + 'static,
    LazyPostS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler,
    PostH: RelocationHandler,
{
    /// Sets the preferred symbol lookup strategy.
    ///
    /// During relocation, symbols are searched here first before checking the
    /// relocation scope or any fallback lookup strategy.
    pub fn pre_find<NewPreS>(
        self,
        pre_find: NewPreS,
    ) -> Relocator<T, NewPreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
    where
        NewPreS: SymbolLookup,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }

    /// Sets the preferred relocation-time symbol lookup using a closure.
    pub fn pre_find_fn<F>(
        self,
        pre_find: F,
    ) -> Relocator<T, F, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
    where
        F: Fn(&str) -> Option<*const ()>,
    {
        self.pre_find(pre_find)
    }

    /// Sets the fallback symbol lookup strategy using a closure.
    ///
    /// During relocation, this strategy is consulted only after the preferred
    /// lookup and the current relocation scope have been exhausted.
    pub fn post_find_fn<F>(
        self,
        post_find: F,
    ) -> Relocator<T, PreS, F, LazyPreS, LazyPostS, PreH, PostH, D>
    where
        F: Fn(&str) -> Option<*const ()>,
    {
        self.post_find(post_find)
    }

    /// Sets the fallback symbol lookup strategy.
    ///
    /// During relocation, this strategy is consulted only after the preferred
    /// lookup and the current relocation scope have been exhausted.
    pub fn post_find<NewPostS>(
        self,
        post_find: NewPostS,
    ) -> Relocator<T, PreS, NewPostS, LazyPreS, LazyPostS, PreH, PostH, D>
    where
        NewPostS: SymbolLookup,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }

    /// Replaces the current symbol-resolution scope.
    ///
    /// During relocation, symbols from these modules are searched in the provided order.
    /// Scope entries are retained as dependencies of the relocated output.
    pub fn scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: core::borrow::Borrow<LoadedCore<D>>,
    {
        let scope: Vec<_> = scope.into_iter().map(|r| r.borrow().clone()).collect();
        self.scope = Arc::from(scope);
        self
    }

    /// Replaces the current symbol-resolution scope with a shared scope owner.
    ///
    /// Scope entries are searched in order and retained as dependencies of the
    /// relocated output.
    pub fn shared_scope(mut self, scope: Arc<[LoadedCore<D>]>) -> Self {
        self.scope = scope;
        self
    }

    /// Appends more modules to the symbol-resolution scope.
    ///
    /// During relocation, additional modules are searched after the existing
    /// scope entries. Scope entries are retained as dependencies of the
    /// relocated output.
    pub fn extend_scope<I, R>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: core::borrow::Borrow<LoadedCore<D>>,
    {
        let mut extended = Vec::with_capacity(self.scope.len());
        extended.extend(self.scope.iter().cloned());
        extended.extend(scope.into_iter().map(|r| r.borrow().clone()));
        self.scope = Arc::from(extended);
        self
    }

    /// Attaches an object and selects the user-data type carried by that object.
    pub fn with_object<U, NewD>(
        self,
        object: U,
    ) -> Relocator<U, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, NewD>
    where
        U: Relocatable<NewD>,
    {
        Relocator {
            object,
            scope: empty_scope(),
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }

    /// Sets the relocation handler that runs before the built-in logic.
    ///
    /// This is useful for intercepting selected relocations or providing
    /// custom behavior before the default implementation runs.
    pub fn pre_handler<NewPreH>(
        self,
        handler: NewPreH,
    ) -> Relocator<T, PreS, PostS, LazyPreS, LazyPostS, NewPreH, PostH, D>
    where
        NewPreH: RelocationHandler,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }

    /// Sets the relocation handler that runs after the built-in logic.
    ///
    /// This handler is called only if the relocation was not already handled
    /// by the pre-handler or the default relocation logic.
    pub fn post_handler<NewPostH>(
        self,
        handler: NewPostH,
    ) -> Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, NewPostH, D>
    where
        NewPostH: RelocationHandler,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: handler,
            binding: self.binding,
        }
    }

    /// Overrides the relocation binding mode.
    pub fn binding(mut self, binding: BindingMode) -> Self {
        self.binding = binding;
        self
    }

    #[inline]
    pub fn set_binding(&mut self, binding: BindingMode) {
        self.binding = binding;
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
where
    T: Relocatable<D>,
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyPreS: SymbolLookup + Send + Sync + 'static,
    LazyPostS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler,
    PostH: RelocationHandler,
{
    /// Executes relocation with the current configuration.
    ///
    /// This consumes the builder, resolves relocations, retains the configured
    /// relocation scope as dependencies, and returns the final loaded image.
    ///
    /// The relocation backend is selected automatically from the relocated
    /// object's [`Relocatable::Arch`]: native images use
    /// [`crate::arch::NativeArch`] (the default) and run target init arrays,
    /// IFUNC resolvers,
    /// lazy-binding trampolines, and TLS resolver stubs as usual;
    /// cross-architecture images carry their own backend with
    /// `SUPPORTS_NATIVE_RUNTIME == false`, which skips those host-side
    /// runtime hooks and rejects explicitly requested lazy binding.
    pub fn relocate(self) -> Result<T::Output> {
        let Self {
            object,
            scope,
            pre_find,
            post_find,
            lazy_pre_find,
            lazy_post_find,
            pre_handler,
            post_handler,
            binding,
        } = self;

        object.relocate(RelocateArgs::new(
            scope,
            binding,
            LookupHooks::new(&pre_find, &post_find),
            LazyLookupHooks::new(lazy_pre_find, lazy_post_find),
            HandlerHooks::new(&pre_handler, &post_handler),
        ))
    }
}

impl<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
    Relocator<T, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, D>
where
    T: SupportLazy,
    PreS: SymbolLookup,
    PostS: SymbolLookup,
    LazyPreS: SymbolLookup + Send + Sync + 'static,
    LazyPostS: SymbolLookup + Send + Sync + 'static,
    PreH: RelocationHandler,
    PostH: RelocationHandler,
{
    /// Forces eager binding.
    pub fn eager(mut self) -> Self {
        self.binding = BindingMode::Eager;
        self
    }

    /// Forces lazy binding.
    pub fn lazy(mut self) -> Self {
        self.binding = BindingMode::Lazy;
        self
    }

    /// Sets the preferred symbol lookup used during lazy binding fixups.
    pub fn lazy_pre_find<NewLazyPreS>(
        self,
        lazy_pre_find: NewLazyPreS,
    ) -> Relocator<T, PreS, PostS, NewLazyPreS, LazyPostS, PreH, PostH, D>
    where
        NewLazyPreS: SymbolLookup + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find,
            lazy_post_find: self.lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }

    /// Sets the preferred lazy-binding lookup using a closure.
    pub fn lazy_pre_find_fn<F>(
        self,
        lazy_pre_find: F,
    ) -> Relocator<T, PreS, PostS, F, LazyPostS, PreH, PostH, D>
    where
        F: Fn(&str) -> Option<*const ()> + Send + Sync + 'static,
    {
        self.lazy_pre_find(lazy_pre_find)
    }

    /// Sets the fallback symbol lookup used during lazy binding fixups.
    pub fn lazy_post_find<NewLazyPostS>(
        self,
        lazy_post_find: NewLazyPostS,
    ) -> Relocator<T, PreS, PostS, LazyPreS, NewLazyPostS, PreH, PostH, D>
    where
        NewLazyPostS: SymbolLookup + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find,
            post_find: self.post_find,
            lazy_pre_find: self.lazy_pre_find,
            lazy_post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }

    /// Sets the fallback lazy-binding lookup using a closure.
    pub fn lazy_post_find_fn<F>(
        self,
        lazy_post_find: F,
    ) -> Relocator<T, PreS, PostS, LazyPreS, F, PreH, PostH, D>
    where
        F: Fn(&str) -> Option<*const ()> + Send + Sync + 'static,
    {
        self.lazy_post_find(lazy_post_find)
    }

    /// Reuses relocate-time symbol lookups for lazy binding fixups.
    pub fn share_find_with_lazy(self) -> Relocator<T, PreS, PostS, PreS, PostS, PreH, PostH, D>
    where
        PreS: Clone + Send + Sync + 'static,
        PostS: Clone + Send + Sync + 'static,
    {
        Relocator {
            object: self.object,
            scope: self.scope,
            pre_find: self.pre_find.clone(),
            post_find: self.post_find.clone(),
            lazy_pre_find: self.pre_find,
            lazy_post_find: self.post_find,
            pre_handler: self.pre_handler,
            post_handler: self.post_handler,
            binding: self.binding,
        }
    }
}

/// A wrapper type for relocation values, providing type safety and arithmetic operations.
///
/// This type represents computed addresses or offsets used in relocations.
/// It supports addition and subtraction for address calculations.
#[must_use = "relocation arithmetic returns a new value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct RelocValue<T>(T);

pub(crate) type RelocAddr = RelocValue<usize>;
#[cfg(feature = "object")]
pub(crate) type RelocSWord32 = RelocValue<i32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationValueFormula {
    Absolute,
    RelativeToPlace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationValueKind {
    None,
    Address(RelocationValueFormula),
    Word32(RelocationValueFormula),
    SWord32(RelocationValueFormula),
}

impl<T> RelocValue<T> {
    #[inline]
    pub const fn new(val: T) -> Self {
        Self(val)
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl RelocAddr {
    #[inline]
    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize)
    }

    #[inline]
    pub fn null() -> Self {
        Self::from_ptr(null::<()>())
    }

    #[inline]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub const fn offset(self, rhs: usize) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    #[inline]
    pub const fn addend(self, rhs: isize) -> Self {
        Self(self.0.wrapping_add_signed(rhs))
    }

    #[inline]
    #[cfg(any(feature = "tls", feature = "object"))]
    pub const fn relative_to(self, place: usize) -> Self {
        Self(self.0.wrapping_sub(place))
    }

    #[inline]
    #[cfg(feature = "object")]
    pub fn try_into_sword32(self) -> Result<RelocSWord32> {
        i32::try_from(self.0 as isize)
            .map(RelocValue::new)
            .map_err(|_| RelocationError::IntegerConversionOverflow.into())
    }
}

impl RelocationValueFormula {
    #[inline]
    fn compute(self, target: usize, addend: isize, place: usize) -> i128 {
        let target = target as i128;
        let addend = addend as i128;
        let place = place as i128;

        match self {
            RelocationValueFormula::Absolute => target + addend,
            RelocationValueFormula::RelativeToPlace => target + addend - place,
        }
    }
}

pub(crate) trait RelocationValueProvider {
    fn relocation_value_kind(
        _relocation_type: usize,
    ) -> core::result::Result<RelocationValueKind, RelocationError> {
        Err(RelocationError::UnsupportedRelocationType)
    }

    fn relocation_value<T>(
        relocation_type: usize,
        target: usize,
        addend: isize,
        place: usize,
        skip: impl FnOnce(RelocValue<()>) -> T,
        write_addr: impl FnOnce(RelocAddr) -> T,
        write_word32: impl FnOnce(RelocValue<u32>) -> T,
        write_sword32: impl FnOnce(RelocValue<i32>) -> T,
    ) -> core::result::Result<T, RelocationError> {
        let kind = Self::relocation_value_kind(relocation_type)?;
        match kind {
            RelocationValueKind::None => Ok(skip(RelocValue::new(()))),
            RelocationValueKind::Address(formula) => Ok(write_addr(RelocAddr::new(
                formula.compute(target, addend, place) as usize,
            ))),
            RelocationValueKind::Word32(formula) => {
                u32::try_from(formula.compute(target, addend, place))
                    .map(RelocValue::new)
                    .map(write_word32)
                    .map_err(|_| RelocationError::IntegerConversionOverflow)
            }
            RelocationValueKind::SWord32(formula) => {
                i32::try_from(formula.compute(target, addend, place))
                    .map(RelocValue::new)
                    .map(write_sword32)
                    .map_err(|_| RelocationError::IntegerConversionOverflow)
            }
        }
    }
}

/// Resolve the final address for an IFUNC resolver entry.
///
/// # Safety
/// The address must point to a valid IFUNC resolver function.
#[inline(always)]
pub(crate) unsafe fn resolve_ifunc(addr: RelocAddr) -> RelocAddr {
    let ifunc: fn() -> usize = unsafe { core::mem::transmute(addr.into_inner()) };
    RelocAddr::new(ifunc())
}

#[cfg(feature = "object")]
impl RelocSWord32 {
    #[inline]
    pub const fn to_ne_bytes(self) -> [u8; 4] {
        self.0.to_ne_bytes()
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
    pub(crate) fn convert(self) -> RelocAddr {
        if likely(self.sym.is_some()) {
            let base = self.lib.base_addr();
            let sym = unsafe { self.sym.unwrap_unchecked() };
            let addr = base.offset(sym.st_value());
            if likely(sym.symbol_type() != ElfSymbolType::GNU_IFUNC) {
                addr
            } else {
                unsafe { resolve_ifunc(addr) }
            }
        } else {
            // 未定义的弱符号返回null
            RelocAddr::null()
        }
    }
}

/// Creates a detailed relocation error.
///
/// The dynamic parts are stored structurally and formatted only in `Display`.
#[cold]
pub(crate) fn reloc_error<A, D>(
    rel: &ElfRelType,
    reason: RelocationFailureReason,
    lib: &ElfCore<D>,
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
/// Returns the resolved address.
#[inline]
pub(crate) fn find_symbol_addr<PreS, PostS, D>(
    pre_find: &PreS,
    post_find: &PostS,
    core: &ElfCore<D>,
    symtab: &SymbolTable,
    scope: &[LoadedCore<D>],
    r_sym: usize,
) -> Option<RelocAddr>
where
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

pub(crate) fn find_symdef_impl<'lib, D>(
    core: &'lib ElfCore<D>,
    scope: &'lib [LoadedCore<D>],
    sym: &'lib ElfSymbol,
    syminfo: &SymbolInfo,
) -> Option<SymDef<'lib, D>> {
    if unlikely(sym.is_local()) {
        Some(SymDef {
            sym: Some(sym),
            lib: core,
        })
    } else {
        let mut precompute = syminfo.precompute();
        scope
            .iter()
            .find_map(|lib| {
                lib.symtab()
                    .lookup_filter(syminfo, &mut precompute)
                    .map(|sym| {
                        logging::trace!(
                            "binding file [{}] to [{}]: symbol [{}]",
                            core.name(),
                            lib.name(),
                            syminfo.name()
                        );
                        SymDef {
                            sym: Some(sym),
                            lib: &lib.core,
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
