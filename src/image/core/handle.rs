use super::CoreInner;
use crate::{
    Result,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, ElfSymbol, PreCompute, SymbolInfo, SymbolTable},
    image::{DynamicInfo, Module, SymbolExports, exports_handle},
    input::{Path, PathBuf},
    memory::{HostRegion, ImageMemory, MappedView, RegionAccess, VmAddr, VmOffset},
    observer::Finalizer,
    relocation::RelocationArch,
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering, Weak},
    tls::{CoreTlsState, TlsDescArgs, TlsModuleId, TlsTpOffset},
};
use alloc::vec::Vec;
use core::{any::Any, cell::OnceCell, fmt::Debug, ptr::NonNull};

/// A non-owning reference to an [`ElfCore`].
///
/// `ElfCoreRef` holds a weak reference to the shared core allocation. It is useful
/// when you want to avoid extending the lifetime of a loaded image unnecessarily
/// or need to detect when the image has been dropped.
pub struct ElfCoreRef<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    /// Weak reference to the shared core allocation.
    inner: Weak<CoreInner<D, Arch, R>>,
}

// Keep this impl manual so cloning a weak core handle does not require D, Arch, or R to be Clone.
impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Clone for ElfCoreRef<D, Arch, R> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> ElfCoreRef<D, Arch, R> {
    /// Attempts to upgrade the weak pointer to an [`ElfCore`].
    ///
    /// # Returns
    /// * `Some(ElfCore)` - If the component is still alive and the upgrade is successful.
    /// * `None` - If the [`ElfCore`] has been dropped.
    pub fn upgrade(&self) -> Option<ElfCore<D, Arch, R>> {
        self.inner.upgrade().map(|inner| ElfCore { inner })
    }
}

/// Shared core state for a loaded ELF image.
///
/// `ElfCore` stores metadata, runtime exports, segments, TLS state, and lifecycle
/// handlers behind an [`Arc`]. Higher-level image wrappers delegate most common
/// operations to this type.
pub struct ElfCore<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    /// Shared reference to the inner component data.
    pub(crate) inner: Arc<CoreInner<D, Arch, R>>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Clone for ElfCore<D, Arch, R> {
    /// Clones the [`ElfCore`], incrementing the internal reference count.
    fn clone(&self) -> Self {
        ElfCore {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> ElfCore<D, Arch, R> {
    /// Returns whether the ELF object has been initialized.
    #[inline]
    pub fn is_init(&self) -> bool {
        self.inner.is_init.load(Ordering::Relaxed)
    }

    /// Marks the component as initialized
    #[inline]
    pub(crate) fn set_init(&self) {
        self.inner.is_init.store(true, Ordering::Relaxed);
    }

    /// Creates a weak reference to this ELF core.
    #[inline]
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch, R> {
        ElfCoreRef {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Gets user data from the ELF object
    #[inline]
    pub fn user_data(&self) -> &D {
        &self.inner.user_data
    }

    /// Returns the program headers of the ELF object.
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        self.inner
            .dynamic_info
            .as_ref()
            .map(|info| info.phdrs.as_slice())
    }

    /// Returns a mutable reference to the user-defined data.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        Arc::get_mut(&mut self.inner).map(|inner| &mut inner.user_data)
    }

    /// Gets the number of strong references to the ELF object
    #[inline]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Gets the number of weak references to the ELF object
    #[inline]
    pub fn weak_count(&self) -> usize {
        Arc::weak_count(&self.inner)
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Returns the ELF module identity used for diagnostics.
    ///
    /// Dynamic images prefer `DT_SONAME`; other images fall back to the basename
    /// of the loader source path.
    #[inline]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Gets the base address of the ELF object
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.inner.segments.base()
    }

    /// Returns the DT_SONAME value when this core has dynamic metadata.
    #[inline]
    pub(crate) fn soname(&self) -> Option<&str> {
        self.inner
            .dynamic_info
            .as_ref()
            .and_then(|info| info.soname)
    }

    /// Returns the mapped segments owned by this image.
    #[inline]
    pub fn segments(&self) -> &ElfSegments<R> {
        &self.inner.segments
    }

    /// Returns the runtime symbol exports used by this image.
    #[inline]
    pub fn exports(&self) -> &dyn SymbolExports<Arch> {
        &*self.inner.exports
    }

    /// Gets the EH frame header pointer
    #[inline]
    pub fn eh_frame_hdr(&self) -> Option<NonNull<u8>> {
        self.inner
            .dynamic_info
            .as_ref()
            .and_then(|info| info.eh_frame_hdr)
    }

    /// Gets the TLS module ID of the ELF object
    #[inline]
    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        self.inner.tls.mod_id()
    }

    /// Gets the TLS thread pointer offset of the ELF object
    #[inline]
    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        self.inner.tls.tp_offset()
    }

    #[inline]
    pub(crate) fn tls_get_addr(&self) -> VmAddr {
        self.inner.tls.tls_get_addr()
    }

    /// Set the TLS descriptor arguments used by dynamic relocation.
    pub(crate) fn set_tls_desc_args(&self, args: TlsDescArgs) {
        self.inner.tls.set_desc_args(args);
    }

    /// Sets the finalizer that will run when the initialized image is dropped.
    pub(crate) fn set_finalizer(&self, finalizer: Finalizer<Arch>) {
        assert!(
            self.inner.finalizer.set(finalizer).is_ok(),
            "finalizer must be set only once",
        );
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> ElfCore<D, Arch, R> {
    /// Creates an `ElfCore` from raw components.
    ///
    /// # Safety
    ///
    /// The caller must ensure these arguments describe a valid loaded dynamic ELF
    /// image and that all borrowed mapped views remain valid for the core's
    /// lifetime.
    #[allow(clippy::too_many_arguments)]
    pub(super) unsafe fn from_raw(
        path: PathBuf,
        base: VmAddr,
        dynamic_entries: MappedView<ElfDyn<Arch::Layout>>,
        dynamic_addr: VmAddr,
        phdrs: Vec<ElfPhdr<Arch::Layout>>,
        eh_frame_hdr: Option<NonNull<u8>>,
        mut segments: ElfSegments<R>,
        tls_mod_id: Option<TlsModuleId>,
        tls_tp_offset: Option<TlsTpOffset>,
        tls_get_addr: VmAddr,
        tls_unregister: fn(TlsModuleId),
        user_data: D,
    ) -> Result<Self> {
        segments.set_base(base);
        let dynamic = ElfDynamic::<Arch>::new(dynamic_entries, dynamic_addr, &segments)?;
        let symtab = SymbolTable::from_dynamic(&dynamic, &segments)?;
        let exports = symtab.clone();
        #[cfg(feature = "lazy-binding")]
        let lazy_symtab = symtab.clone();
        let soname = dynamic
            .soname_off
            .map(|soname_off| symtab.strtab().get_str(soname_off.get()));
        Ok(Self {
            inner: Arc::new(CoreInner {
                path,
                is_init: AtomicBool::new(true),
                exports: exports_handle(exports),
                dynamic_info: Some(Arc::new(DynamicInfo {
                    eh_frame_hdr,
                    phdrs: ElfPhdrs::Vec(phdrs),
                    soname,
                    #[cfg(feature = "lazy-binding")]
                    lazy: crate::image::LazyBindingInfo::new(dynamic.pltrel, lazy_symtab),
                })),
                tls: CoreTlsState::new(tls_mod_id, tls_tp_offset, tls_get_addr, tls_unregister),
                segments,
                finalizer: OnceCell::new(),
                user_data,
            }),
        })
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Debug for ElfCore<D, Arch, R> {
    /// Formats the ElfCore for debugging purposes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfCore")
            .field("path", &self.inner.path)
            .field("base", &format_args!("{}", self.base()))
            .field("tls_mod_id", &self.tls_mod_id())
            .finish()
    }
}

impl<D, Arch, R> Module<Arch> for ElfCore<D, Arch, R>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn name(&self) -> &str {
        ElfCore::name(self)
    }

    #[inline]
    fn lookup_symbol<'source>(
        &'source self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'source ElfSymbol<Arch::Layout>> {
        self.exports().lookup(symbol, precompute)
    }

    #[inline]
    fn base(&self) -> VmAddr {
        ElfCore::base(self)
    }

    #[inline]
    fn read_bytes(&self, offset: VmOffset, dst: &mut [u8]) -> Result<()> {
        self.segments().read_bytes(self.base() + offset, dst)
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        self.segments().host_ptr(addr)
    }

    #[inline]
    fn tls_mod_id(&self) -> Option<TlsModuleId> {
        ElfCore::tls_mod_id(self)
    }

    #[inline]
    fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        ElfCore::tls_tp_offset(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NonCloneData;

    #[test]
    fn weak_core_ref_clone_does_not_require_user_data_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<ElfCoreRef<NonCloneData>>();
    }
}
