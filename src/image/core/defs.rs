use crate::{
    Result,
    elf::SymbolEntry,
    image::{DynamicInfo, PltRelocInfo, SymbolExports, WeakModuleScope},
    input::PathBuf,
    logging,
    memory::{HostRegion, ImageMemory, RegionAccess, VmAddr},
    observer::Finalizer,
    relocation::{RelocationArch, find_symdef_impl},
    runtime::CodeExecutor,
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering},
    tls::{CoreTlsState, TLS_GET_ADDR_SYMBOL, TlsResolver},
};
use alloc::boxed::Box;
use core::{any::Any, cell::OnceCell, marker::PhantomData, ops::Deref};

/// Stable runtime header shared by all [`CoreInner`] instantiations.
#[repr(C)]
pub(crate) struct CoreRuntime<Arch: RelocationArch = crate::arch::NativeArch> {
    core: OnceCell<VmAddr>,
    lazy_plt: Option<PltRelocInfo<Arch>>,
    /// Opaque lazy-binding runtime state retained for the module lifetime.
    pub(crate) lazy_runtime: OnceCell<Box<dyn Any + Send + Sync>>,
    module: for<'a> unsafe fn(&'a Self) -> &'a dyn CoreRuntimeModule<Arch>,
}

impl<Arch: RelocationArch> CoreRuntime<Arch> {
    pub(crate) fn new<D, R, Tls>(lazy_plt: Option<PltRelocInfo<Arch>>) -> Self
    where
        D: 'static,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
    {
        Self {
            core: OnceCell::new(),
            lazy_plt,
            lazy_runtime: OnceCell::new(),
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
    pub(crate) fn module(&self) -> &dyn CoreRuntimeModule<Arch> {
        unsafe { (self.module)(self) }
    }
}

pub(crate) trait CoreRuntimeModule<Arch: RelocationArch>: Send + Sync {
    fn memory(&self) -> &dyn ImageMemory;

    fn lookup_symbol(&self, symbol: SymbolEntry<'_, Arch::Layout>) -> Result<Option<VmAddr>>;
}

#[inline]
unsafe fn core_inner<D, Arch, R, Tls>(runtime: &CoreRuntime<Arch>) -> &CoreInner<D, Arch, R, Tls>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    unsafe { &*runtime.core().as_ptr::<CoreInner<D, Arch, R, Tls>>() }
}

unsafe fn core_module<D, Arch, R, Tls>(runtime: &CoreRuntime<Arch>) -> &dyn CoreRuntimeModule<Arch>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    unsafe { core_inner::<D, Arch, R, Tls>(runtime) }
}

impl<D, Arch, R, Tls> CoreRuntimeModule<Arch> for CoreInner<D, Arch, R, Tls>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        &self.segments
    }

    fn lookup_symbol(&self, symbol: SymbolEntry<'_, Arch::Layout>) -> Result<Option<VmAddr>> {
        if Tls::OVERRIDE_TLS_GET_ADDR && symbol.name() == TLS_GET_ADDR_SYMBOL {
            return Tls::bind_tls_get_addr().map(Some);
        }

        let Some(scope) = self.scope.get().and_then(WeakModuleScope::upgrade) else {
            return Ok(None);
        };
        let symbolic = self.dynamic_info.as_ref().is_some_and(|info| info.symbolic);
        let executor = self.executor.as_ref();
        find_symdef_impl(self, &scope, symbol.symbol(), symbol.info(), symbolic)
            .map(|symdef| symdef.resolve_addr(executor))
            .transpose()
    }
}

/// Inner structure for ElfCore
pub(crate) struct CoreInner<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Stable runtime state used by code paths that should not depend on this
    /// struct's generic layout.
    pub(crate) runtime: Box<CoreRuntime<Arch>>,

    /// Executor retained for IFUNC and runtime-code resolution.
    pub(crate) executor: Arc<dyn CodeExecutor<Arch>>,

    /// Indicates whether the component has been initialized
    pub(crate) is_init: AtomicBool,

    /// Loader source path or caller-provided source identifier.
    pub(crate) path: PathBuf,

    /// Runtime exports used for module symbol lookup.
    pub(crate) exports: Arc<dyn SymbolExports<Arch::Layout>>,

    /// Finalization behavior resolved during relocation.
    pub(crate) finalizer: OnceCell<Finalizer>,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo<Arch>>>,

    /// Relocation lookup scope retained for the loaded module lifetime.
    pub(crate) scope: OnceCell<WeakModuleScope<Arch, Tls>>,

    /// TLS runtime state for this loaded object.
    pub(crate) tls: CoreTlsState<Arch, Tls>,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    CoreInner<D, Arch, R, Tls>
{
    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.dynamic_info
            .as_ref()
            .and_then(|info| info.soname)
            .unwrap_or_else(|| self.path.file_name())
    }

    #[inline]
    pub(crate) const fn runtime(&self) -> &CoreRuntime<Arch> {
        &self.runtime
    }

    #[inline]
    pub(crate) fn bind_runtime_owner(inner: &Arc<Self>) {
        inner
            .runtime
            .bind_core(VmAddr::from_ptr(Arc::as_ptr(inner)));
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Drop
    for CoreInner<D, Arch, R, Tls>
{
    /// Executes finalization functions when the component is dropped
    fn drop(&mut self) {
        if self.is_init.load(Ordering::Relaxed)
            && let Some(finalizer) = self.finalizer.take()
        {
            let name = self.name();
            if let Err(err) = finalizer.run(name, &self.segments, self.executor.as_ref()) {
                logging::error!("finalization lifecycle failed for {}: {err}", name);
            }
        }
        self.tls.cleanup();
    }
}

// Safety: CoreInner can be shared between threads.
unsafe impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Sync
    for CoreInner<D, Arch, R, Tls>
{
}
// Safety: CoreInner can be sent between threads.
unsafe impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Send
    for CoreInner<D, Arch, R, Tls>
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
    #[inline]
    pub(crate) const fn from_ptr(ptr: *mut ()) -> Self {
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
