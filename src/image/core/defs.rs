use crate::{
    Result, TlsError,
    arch::NativeArch,
    elf::{ElfSymbol, ElfSymbolType, SymbolEntry},
    image::{
        DynamicInfo, Module, ModuleSearch, ModuleState, PltRelocInfo, SymbolExports,
        WeakLookupScope,
    },
    lazy::{LazySetup, LazyValues},
    logging,
    memory::{HostRegion, ImageMemory, RegionAccess, VmAddr},
    observer::LifecycleHandlers,
    relocation::{RelocationArch, SymDef, SymbolRegistry, SymbolResolver},
    runtime::{CodeContext, CodeExecutor, DomainId},
    segment::ElfSegments,
    sync::{Arc, OnceCell, Weak},
    tls::{CoreTlsState, ModuleTls, TLS_GET_ADDR_SYMBOL, TlsResolver},
};
use alloc::boxed::Box;
use core::{marker::PhantomData, ops::Deref};

/// Stable runtime header shared by all [`CoreInner`] instantiations.
#[repr(C)]
pub(crate) struct CoreRuntime<Arch: RelocationArch = NativeArch> {
    core: OnceCell<VmAddr>,
    lazy_plt: Option<PltRelocInfo<Arch>>,
    /// Lazy-binding values and state retained for the module lifetime.
    lazy: OnceCell<LazySetup>,
    module: for<'a> unsafe fn(&'a Self) -> &'a dyn CoreRuntimeModule<Arch>,
}

impl<Arch: RelocationArch> CoreRuntime<Arch> {
    pub(crate) fn new<D, R, Tls>(lazy_plt: Option<PltRelocInfo<Arch>>) -> Self
    where
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
    {
        Self {
            core: OnceCell::new(),
            lazy_plt,
            lazy: OnceCell::new(),
            module: core_module::<D, Arch, R, Tls>,
        }
    }

    #[inline]
    fn bind_core(&self, core: VmAddr) {
        assert!(
            self.core.set(core).is_ok(),
            "core runtime owner must be installed only once",
        );
    }

    #[inline]
    fn core(&self) -> VmAddr {
        *self
            .core
            .get()
            .expect("core runtime owner must be installed before use")
    }

    #[inline]
    pub(crate) fn lazy_plt(&self) -> Option<&PltRelocInfo<Arch>> {
        self.lazy_plt.as_ref()
    }

    #[inline]
    pub(crate) fn set_lazy(&self, setup: LazySetup) {
        assert!(
            self.lazy.set(setup).is_ok(),
            "lazy binding setup must be installed only once",
        );
    }

    #[inline]
    pub(crate) fn lazy_values(&self) -> Option<LazyValues> {
        self.lazy.get().map(LazySetup::values)
    }

    #[inline]
    pub(crate) fn module(&self) -> &dyn CoreRuntimeModule<Arch> {
        unsafe { (self.module)(self) }
    }
}

pub(crate) trait CoreRuntimeModule<Arch: RelocationArch>: Send + Sync {
    fn memory(&self) -> &dyn ImageMemory;

    fn lookup_symbol(&self, symbol: &SymbolEntry<'_, Arch::Layout>) -> Result<Option<VmAddr>>;
}

#[inline]
unsafe fn core_inner<D, Arch, R, Tls>(runtime: &CoreRuntime<Arch>) -> &CoreInner<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    unsafe { &*runtime.core().as_ptr::<CoreInner<D, Arch, R, Tls>>() }
}

unsafe fn core_module<D, Arch, R, Tls>(runtime: &CoreRuntime<Arch>) -> &dyn CoreRuntimeModule<Arch>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    unsafe { core_inner::<D, Arch, R, Tls>(runtime) }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> CoreRuntimeModule<Arch> for CoreInner<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        &self.segments
    }

    fn lookup_symbol(&self, symbol: &SymbolEntry<'_, Arch::Layout>) -> Result<Option<VmAddr>> {
        if Tls::OVERRIDE_TLS_GET_ADDR && symbol.name() == TLS_GET_ADDR_SYMBOL {
            return self.tls.resolver().bind_tls_get_addr().map(Some);
        }

        let Some(scope) = self.scope.get().and_then(WeakLookupScope::upgrade) else {
            return Ok(None);
        };
        let symbolic = self.dynamic_info.as_ref().is_some_and(|info| info.symbolic);
        let executor = self.executor.as_ref();
        let symbols = self.symbols.get().and_then(Weak::upgrade);
        SymbolResolver::new(self, scope, symbols.as_deref(), symbolic)
            .find(symbol)
            .map(|symdef| symdef.resolve(executor))
            .transpose()
    }
}

/// Inner structure for ElfCore
pub(crate) struct CoreInner<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Stable runtime state used by code paths that should not depend on this
    /// struct's generic layout.
    pub(crate) runtime: Box<CoreRuntime<Arch>>,

    /// Executor retained for IFUNC and runtime-code resolution.
    pub(crate) executor: Arc<dyn CodeExecutor<Arch>>,

    /// Runtime domain in which this image's addresses are meaningful.
    pub(crate) domain: DomainId,

    /// Lifecycle state shared by every handle for this module.
    pub(crate) state: ModuleState,

    /// Initialization and finalization behavior resolved during relocation.
    pub(crate) lifecycle: OnceCell<LifecycleHandlers>,

    /// Filesystem identity and dependency search metadata.
    pub(crate) search: ModuleSearch,

    /// Runtime exports used for module symbol lookup.
    pub(crate) exports: Arc<dyn SymbolExports<Arch::Layout>>,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo<Arch>>>,

    /// Relocation lookup scope retained for the loaded module lifetime.
    pub(crate) scope: OnceCell<WeakLookupScope<Arch, Tls>>,

    /// Namespace symbol state used by deferred lookup.
    pub(crate) symbols: OnceCell<Weak<SymbolRegistry<Arch, Tls>>>,

    /// TLS runtime state for this loaded object.
    pub(crate) tls: CoreTlsState<Arch, Tls>,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    CoreInner<D, Arch, R, Tls>
{
    #[inline]
    pub(crate) fn bind_runtime_owner(inner: &Arc<Self>) {
        inner
            .runtime
            .bind_core(VmAddr::from_ptr(Arc::as_ptr(inner)));
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> Module<Arch, Tls> for CoreInner<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        self.search.name()
    }

    #[inline]
    fn domain_id(&self) -> DomainId {
        self.domain
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        Some(&self.search)
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        &*self.exports
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        &self.segments
    }

    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr> {
        if symbol.symbol_type() == ElfSymbolType::TLS {
            let index = self
                .tls
                .index(symbol.st_value())
                .ok_or(TlsError::TemplateUnavailable)?;
            let resolver = self.tls.resolver().bind_tls_get_addr()?;
            self.executor.resolve_tls(
                CodeContext::new(self.name(), &self.segments),
                resolver,
                index,
            )
        } else {
            SymDef::<Arch, Tls>::defined(symbol, self).resolve(self.executor.as_ref())
        }
    }

    #[inline]
    fn tls(&self) -> Option<ModuleTls> {
        self.tls.module()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        &self.state
    }

    fn initialize(&self) -> Result<()> {
        let initializer = self
            .lifecycle
            .get()
            .expect("lifecycle must be installed before initialization")
            .initializer();
        let executor = self.executor.as_ref();
        initializer.run(self.name(), &self.segments, |ctx, addr| {
            executor.call_lifecycle(ctx, addr)
        })
    }

    fn finalize(&self) -> Result<()> {
        let Some(lifecycle) = self.lifecycle.get() else {
            return Ok(());
        };
        let finalizer = lifecycle.finalizer();
        let executor = self.executor.as_ref();
        finalizer.run(self.name(), &self.segments, |ctx, addr| {
            executor.call_lifecycle(ctx, addr)
        })
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Drop
    for CoreInner<D, Arch, R, Tls>
{
    /// Executes finalization functions when the component is dropped
    fn drop(&mut self) {
        if let Err(err) = self.state.finalize(|| Module::finalize(self)) {
            logging::error!("finalization lifecycle failed for {}: {err}", self.name());
        }
    }
}

// Safety: mutable runtime state is synchronized by atomics or OnceCell. Raw
// mapped views are immutable metadata, and memory access is mediated by the
// Send + Sync RegionAccess implementation.
unsafe impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Sync for CoreInner<D, Arch, R, Tls>
{
}

// Safety: see the Sync implementation above. Every owned field is Send, and
// mapped addresses are values interpreted only through RegionAccess.
unsafe impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Send for CoreInner<D, Arch, R, Tls>
{
}

/// A typed symbol retrieved from a loaded ELF module.
///
/// `Symbol` provides safe access to a function or variable within a loaded library.
/// It carries a lifetime marker `'lib` to ensure that the symbol cannot outlive
/// the library it was loaded from, preventing use-after-free errors.
#[derive(Debug, Clone)]
pub struct Symbol<'lib, T: 'lib> {
    /// Raw pointer to the symbol's memory location.
    ptr: *mut (),

    /// Phantom data to bind the symbol's lifetime to the source library.
    pd: PhantomData<&'lib T>,
}

impl<'lib, T> Deref for Symbol<'lib, T> {
    type Target = T;

    /// Accesses the underlying symbol as a reference to type `T`.
    ///
    /// This allows calling functions or accessing variables directly.
    fn deref(&self) -> &T {
        unsafe { &*(&self.ptr as *const *mut _ as *const T) }
    }
}

impl<'lib, T> Symbol<'lib, T> {
    /// Creates a symbol handle from a raw runtime address.
    ///
    /// # Safety
    /// The caller must ensure `ptr` points to a valid symbol of type `T`
    /// and that the referenced code or data outlives `'lib`.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut ()) -> Self {
        Self {
            ptr,
            pd: PhantomData,
        }
    }

    /// Consumes the `Symbol` and returns its raw memory address.
    ///
    /// # Returns
    /// A raw pointer to the symbol data.
    pub fn into_raw(self) -> *const () {
        self.ptr
    }
}

// Safety: Symbol can be sent between threads if T can
unsafe impl<T: Send> Send for Symbol<'_, T> {}

// Safety: Symbol can be shared between threads if T can
unsafe impl<T: Sync> Sync for Symbol<'_, T> {}
