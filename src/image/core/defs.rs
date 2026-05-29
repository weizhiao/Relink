use crate::{
    elf::{HashTable, Lifecycle, SymbolTable},
    image::DynamicInfo,
    input::PathBuf,
    logging,
    observer::{
        LifecycleEvent, LifecyclePhase, ModuleUnloadEvent, SharedLifecycleExecutor,
        SharedModuleUnloadHook,
    },
    os::{HostRegion, RegionAccess},
    relocation::RelocationArch,
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering},
    tls::CoreTlsState,
};
use core::{cell::OnceCell, marker::PhantomData, ops::Deref};

/// Inner structure for ElfCore
#[repr(C)]
pub(crate) struct CoreInner<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    /// Indicates whether the component has been initialized
    pub(crate) is_init: AtomicBool,

    /// Loader source path or caller-provided source identifier.
    pub(crate) path: PathBuf,

    /// ELF symbols table
    pub(crate) symtab: SymbolTable<Arch::Layout, H>,

    /// Finalization functions resolved during relocation.
    pub(crate) fini: OnceCell<Lifecycle>,

    /// Native finalization executor.
    pub(crate) fini_executor: OnceCell<SharedLifecycleExecutor<R>>,

    /// Optional callback installed by the relocation observer for unload.
    pub(crate) unload_hook: OnceCell<SharedModuleUnloadHook<D, Arch, R, H>>,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo<Arch>>>,

    /// TLS runtime state for the loaded object.
    pub(crate) tls: CoreTlsState,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, H> CoreInner<D, Arch, R, H> {
    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.dynamic_info
            .as_ref()
            .and_then(|info| info.soname)
            .unwrap_or_else(|| self.path.file_name())
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, H> Drop for CoreInner<D, Arch, R, H> {
    /// Executes finalization functions when the component is dropped
    fn drop(&mut self) {
        if self.is_init.load(Ordering::Relaxed)
            && let Some(fini) = self.fini.get()
        {
            let executor = self
                .fini_executor
                .get()
                .expect("finalization executor must be set with finalization lifecycle")
                .clone();
            let name = self.name();
            let mut event = LifecycleEvent::with_executor(
                LifecyclePhase::Fini,
                name,
                fini,
                &self.segments,
                executor,
            );
            event.run();
        }
        if let Some(unload_hook) = self.unload_hook.get() {
            let name = self.name();
            let event = ModuleUnloadEvent::new(self);
            if let Err(err) = unload_hook(event) {
                logging::error!("module unload hook failed for {}: {err}", name);
            }
        }
        self.tls.cleanup();
    }
}

// Safety: CoreInner can be shared between threads.
unsafe impl<D: 'static, Arch: RelocationArch, R: RegionAccess, H> Sync
    for CoreInner<D, Arch, R, H>
{
}
// Safety: CoreInner can be sent between threads.
unsafe impl<D: 'static, Arch: RelocationArch, R: RegionAccess, H> Send
    for CoreInner<D, Arch, R, H>
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
    pub(crate) ptr: *mut (),

    /// Phantom data to bind the symbol's lifetime to the source library.
    pub(crate) pd: PhantomData<&'lib T>,
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
