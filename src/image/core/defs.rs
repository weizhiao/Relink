use crate::{
    image::{DynamicInfo, SymbolExports},
    input::PathBuf,
    logging,
    memory::{HostRegion, RegionAccess},
    observer::Finalizer,
    relocation::RelocationArch,
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering},
    tls::{CoreTlsDescArgs, CoreTlsState, TlsResolver},
};
use core::{cell::OnceCell, marker::PhantomData, ops::Deref};

/// Inner structure for ElfCore
#[repr(C)]
pub(crate) struct CoreInner<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver = (),
> {
    /// Indicates whether the component has been initialized
    pub(crate) is_init: AtomicBool,

    /// Loader source path or caller-provided source identifier.
    pub(crate) path: PathBuf,

    /// Runtime exports used for module symbol lookup.
    pub(crate) exports: Arc<dyn SymbolExports<Arch::Layout>>,

    /// Finalization behavior resolved during relocation.
    pub(crate) finalizer: OnceCell<Finalizer<Arch>>,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo<Arch, Tls>>>,

    /// TLS runtime state for this loaded object.
    pub(crate) tls: CoreTlsState<Tls>,

    /// Backing storage for TLSDESC relocation arguments written into this image.
    pub(crate) tls_desc_args: CoreTlsDescArgs,

    /// Memory segments
    pub(crate) segments: ElfSegments<R>,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver>
    CoreInner<D, Arch, R, Tls>
{
    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.dynamic_info
            .as_ref()
            .and_then(|info| info.soname)
            .unwrap_or_else(|| self.path.file_name())
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Drop
    for CoreInner<D, Arch, R, Tls>
{
    /// Executes finalization functions when the component is dropped
    fn drop(&mut self) {
        if self.is_init.load(Ordering::Relaxed)
            && let Some(finalizer) = self.finalizer.take()
        {
            let name = self.name();
            if let Err(err) = finalizer.run(name, &self.segments) {
                logging::error!("finalization lifecycle failed for {}: {err}", name);
            }
        }
        self.tls.cleanup();
    }
}

// Safety: CoreInner can be shared between threads.
unsafe impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Sync
    for CoreInner<D, Arch, R, Tls>
{
}
// Safety: CoreInner can be sent between threads.
unsafe impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver> Send
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
