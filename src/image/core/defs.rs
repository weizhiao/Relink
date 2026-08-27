use crate::{
    Result, TlsError,
    arch::NativeArch,
    elf::{ElfPhdr, ElfSymbol, ElfSymbolType, SymbolEntry},
    image::{
        DynamicInfo, GlobalScope, Module, ModuleHandle, ModuleSearch, ModuleState, PltRelocInfo,
        SymbolExports, WeakLocalScope,
    },
    input::Path,
    lazy::{LazySetup, LazyValues},
    logging,
    memory::{HostRegion, ImageMemory, RegionAccess, VmAddr, VmOffset},
    observer::LifecycleHandlers,
    relocation::{LookupOrder, RelocationArch, SymbolRegistry, SymbolResolver},
    runtime::{CodeContext, CodeExecutor, DomainId},
    segment::{ElfSegments, MappedRange},
    sync::{Arc, OnceCell, Weak},
    tls::{CoreTlsState, ModuleTls, TLS_GET_ADDR_SYMBOL, TlsResolver},
};
use alloc::boxed::Box;
use core::{marker::PhantomData, ops::Deref, ptr::NonNull};

/// Stable runtime header shared by all [`ElfModule`] instantiations.
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

pub(crate) struct LazyLookup<Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    pub(super) source: Weak<dyn Module<Arch, Tls>>,
    pub(super) scope: WeakLocalScope<Arch, Tls>,
    pub(super) symbols: Option<Weak<SymbolRegistry<Arch, Tls>>>,
    pub(super) order: LookupOrder,
}

#[inline]
unsafe fn elf_module<D, Arch, R, Tls>(runtime: &CoreRuntime<Arch>) -> &ElfModule<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    unsafe { &*runtime.core().as_ptr::<ElfModule<D, Arch, R, Tls>>() }
}

unsafe fn core_module<D, Arch, R, Tls>(runtime: &CoreRuntime<Arch>) -> &dyn CoreRuntimeModule<Arch>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    unsafe { elf_module::<D, Arch, R, Tls>(runtime) }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> CoreRuntimeModule<Arch> for ElfModule<D, Arch, R, Tls>
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

        let Some(lazy) = self.lazy_lookup.get() else {
            return Ok(None);
        };
        let Some(source) = lazy.source.upgrade().map(ModuleHandle::from_shared) else {
            return Ok(None);
        };
        let Some(lookup) = lazy.scope.upgrade_local() else {
            return Ok(None);
        };
        let global = lazy.scope.upgrade_global();
        // Serialize lookup plus dependency recording with global-scope removal.
        let global_guard = global.as_ref().map(GlobalScope::read);
        let symbolic = self.dynamic_info.as_ref().is_some_and(|info| info.symbolic);
        let symbols = lazy.symbols.as_ref().and_then(Weak::upgrade);
        let resolver = SymbolResolver::new(
            &source,
            lookup,
            global_guard.as_deref(),
            symbols.as_deref(),
            symbolic,
            lazy.order,
        );
        let Some(symdef) = resolver.find(symbol) else {
            return Ok(None);
        };
        let effect = symdef.effect();
        let pin = effect.pin();
        source.state().install_effects(effect.provider, pin);
        if let (Some(symbols), Some(pin)) = (symbols.as_ref(), pin) {
            symbols.queue_pin(pin);
        }
        symdef.resolve().map(Some)
    }
}

/// Shared allocation backing one loaded ELF module.
///
/// `ElfModule` is the concrete module type stored by [`ModuleHandle`] for ELF
/// images managed by [`crate::LinkContext`]. Its fields remain private to
/// Relink, while its read-only methods expose ELF metadata and caller data
/// without another allocation or a capability wrapper.
pub struct ElfModule<
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

    /// Lifecycle state shared by every handle for this module.
    pub(crate) state: ModuleState,

    /// Initialization and finalization behavior resolved during relocation.
    pub(crate) lifecycle: OnceCell<LifecycleHandlers>,

    /// Dependency search metadata.
    pub(crate) search: ModuleSearch,

    /// Runtime exports used for module symbol lookup.
    pub(crate) exports: Arc<dyn SymbolExports<Arch::Layout>>,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo<Arch>>>,

    /// Weak state used by lazy symbol lookup without retaining dependencies.
    pub(crate) lazy_lookup: OnceCell<LazyLookup<Arch, Tls>>,

    /// TLS runtime state for this loaded object.
    pub(crate) tls: CoreTlsState<Arch, Tls>,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    ElfModule<D, Arch, R, Tls>
{
    /// Returns the runtime domain in which this ELF image's addresses are meaningful.
    #[inline]
    pub fn domain_id(&self) -> DomainId {
        self.state.domain_id()
    }

    /// Runs this ELF module's initialization lifecycle at most once.
    #[inline]
    pub fn initialize(&self) -> Result<()> {
        self.state.initialize(|| Module::initialize(self))
    }

    /// Returns the ELF module name used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.search.name()
    }

    /// Returns the `DT_SONAME` value, when present.
    #[inline]
    pub fn soname(&self) -> Option<&str> {
        self.search.soname()
    }

    /// Returns the canonical identity, domain, and lifecycle state.
    #[inline]
    pub const fn state(&self) -> &ModuleState {
        &self.state
    }

    /// Returns TLS metadata when this image owns a TLS block.
    #[inline]
    pub fn tls(&self) -> Option<ModuleTls> {
        self.tls.module()
    }

    /// Returns caller-owned data associated with this ELF module.
    #[inline]
    pub const fn user_data(&self) -> &D {
        &self.user_data
    }

    /// Returns the retained program headers, when available.
    #[inline]
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        self.dynamic_info.as_ref().map(|info| info.phdrs.as_slice())
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.search.path()
    }

    /// Returns the names recorded by `DT_NEEDED`.
    #[inline]
    pub fn needed_libs(&self) -> &[&str] {
        self.dynamic_info
            .as_ref()
            .map_or(&[], |info| info.needed_libs.as_ref())
    }

    /// Returns the mapped segments owned by this ELF image.
    #[inline]
    pub const fn segments(&self) -> &ElfSegments<R> {
        &self.segments
    }

    /// Returns the mapped module-relative ranges owned by this ELF image.
    #[inline]
    pub fn mapped_ranges(&self) -> &[MappedRange] {
        self.segments.ranges()
    }

    /// Returns the `PT_GNU_EH_FRAME` header address, when present.
    #[inline]
    pub fn eh_frame_hdr(&self) -> Option<NonNull<u8>> {
        self.dynamic_info
            .as_ref()
            .and_then(|info| info.eh_frame_hdr)
    }

    #[inline]
    pub(crate) fn set_lifecycle(&self, lifecycle: LifecycleHandlers) {
        assert!(
            self.lifecycle.set(lifecycle).is_ok(),
            "lifecycle must be set only once",
        );
    }

    #[inline]
    pub(crate) fn symbolic(&self) -> bool {
        self.dynamic_info.as_ref().is_some_and(|info| info.symbolic)
    }

    #[inline]
    pub(crate) fn tls_resolver(&self) -> &Tls {
        self.tls.resolver()
    }

    #[inline]
    pub(crate) fn executor(&self) -> &dyn CodeExecutor<Arch> {
        self.executor.as_ref()
    }

    #[inline]
    pub(crate) fn bind_runtime_owner(inner: &Arc<Self>) {
        inner
            .runtime
            .bind_core(VmAddr::from_ptr(Arc::as_ptr(inner)));
    }

    #[cold]
    #[inline(never)]
    fn resolve_ifunc(&self, resolver: VmAddr) -> Result<VmAddr> {
        self.executor.resolve_ifunc(
            CodeContext::<Arch>::new(self.search.name(), &self.segments),
            resolver,
        )
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> Module<Arch, Tls> for ElfModule<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        self.name()
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        Some(&self.search)
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        self.exports.as_ref()
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
            let addr = if symbol.st_shndx().is_abs() {
                VmAddr::new(symbol.st_value())
            } else {
                self.segments.base() + VmOffset::new(symbol.st_value())
            };
            if symbol.symbol_type() == ElfSymbolType::GNU_IFUNC {
                self.resolve_ifunc(addr)
            } else {
                Ok(addr)
            }
        }
    }

    #[inline]
    fn tls(&self) -> Option<ModuleTls> {
        self.tls()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        self.state()
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
    for ElfModule<D, Arch, R, Tls>
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
    Sync for ElfModule<D, Arch, R, Tls>
{
}

// Safety: see the Sync implementation above. Every owned field is Send, and
// mapped addresses are values interpreted only through RegionAccess.
unsafe impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    Send for ElfModule<D, Arch, R, Tls>
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
