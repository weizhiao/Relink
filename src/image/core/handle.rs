use super::CoreInner;
use crate::{
    Result, TlsError,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, SymbolTable},
    image::{DynamicInfo, Module, ModuleTls, SymbolExports, exports_handle},
    input::{Path, PathBuf},
    memory::{HostRegion, ImageMemory, MappedView, RegionAccess, VmAddr},
    observer::Finalizer,
    relocation::RelocationArch,
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering, Weak},
    tls::{
        CoreTlsState, TlsImageProvider, TlsImageSource, TlsInfo, TlsModuleId, TlsResolver,
        TlsTemplate, TlsTpOffset, tls_image_provider_handle,
    },
};
use alloc::vec::Vec;
use core::{cell::OnceCell, fmt::Debug, marker::PhantomData, ptr::NonNull};

/// A non-owning reference to an [`ElfCore`].
///
/// `ElfCoreRef` holds a weak reference to the shared core allocation. It is useful
/// when you want to avoid extending the lifetime of a loaded image unnecessarily
/// or need to detect when the image has been dropped.
pub struct ElfCoreRef<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Weak reference to the shared core allocation.
    inner: Weak<CoreInner<D, Arch, R, Tls>>,
}

// Keep this impl manual so cloning a weak core handle does not require D, Arch, or R to be Clone.
impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for ElfCoreRef<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    ElfCoreRef<D, Arch, R, Tls>
{
    /// Attempts to upgrade the weak pointer to an [`ElfCore`].
    ///
    /// # Returns
    /// * `Some(ElfCore)` - If the component is still alive and the upgrade is successful.
    /// * `None` - If the [`ElfCore`] has been dropped.
    pub fn upgrade(&self) -> Option<ElfCore<D, Arch, R, Tls>> {
        self.inner.upgrade().map(|inner| ElfCore { inner })
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> TlsImageProvider
    for CoreInner<D, Arch, R, Tls>
{
    fn with_tls_template(&self, f: &mut dyn FnMut(TlsTemplate<'_>) -> Result<()>) -> Result<()> {
        if self.tls.info().is_none() {
            return Err(TlsError::TemplateUnavailable.into());
        }
        self.tls.with_template(f)
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
    Tls: TlsResolver<Arch> = (),
> {
    /// Shared reference to the inner component data.
    pub(crate) inner: Arc<CoreInner<D, Arch, R, Tls>>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for ElfCore<D, Arch, R, Tls>
{
    /// Clones the [`ElfCore`], incrementing the internal reference count.
    fn clone(&self) -> Self {
        ElfCore {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static>
    ElfCore<D, Arch, R, Tls>
{
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
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch, R, Tls> {
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

    /// Returns whether dynamic relocations in this image prefer definitions from itself.
    #[inline]
    pub(crate) fn symbolic(&self) -> bool {
        self.inner
            .dynamic_info
            .as_ref()
            .is_some_and(|info| info.symbolic)
    }

    /// Returns the mapped segments owned by this image.
    #[inline]
    pub fn segments(&self) -> &ElfSegments<R> {
        &self.inner.segments
    }

    /// Returns the runtime symbol exports used by this image.
    #[inline]
    pub fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
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

    /// Returns TLS metadata associated with this image.
    #[inline]
    pub fn tls(&self) -> ModuleTls {
        ModuleTls::new(self.inner.tls.mod_id(), self.inner.tls.tp_offset())
    }

    pub(crate) fn init_tls(&self) -> Result<()> {
        let Some(info) = self.inner.tls.info() else {
            return Ok(());
        };
        let provider = tls_image_provider_handle(self.inner.clone());
        self.inner
            .tls
            .init_tls(TlsImageSource::new(info, Arc::downgrade(&provider)))
    }

    pub(crate) fn tls_addr(&self, offset: usize) -> Option<VmAddr> {
        self.inner.tls.addr(offset)
    }

    /// Sets the finalizer that will run when the initialized image is dropped.
    pub(crate) fn set_finalizer(&self, finalizer: Finalizer<Arch>) {
        assert!(
            self.inner.finalizer.set(finalizer).is_ok(),
            "finalizer must be set only once",
        );
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    ElfCore<D, Arch, R, Tls>
{
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
        tls_info: Option<TlsInfo>,
        tls_image: Option<MappedView<u8>>,
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
                dynamic_info: Some(Arc::new(DynamicInfo::<Arch, Tls> {
                    eh_frame_hdr,
                    phdrs: ElfPhdrs::Vec(phdrs),
                    soname,
                    symbolic: dynamic.symbolic,
                    #[cfg(feature = "lazy-binding")]
                    lazy: crate::image::LazyBindingInfo::new(dynamic.pltrel, lazy_symtab),
                    _tls: PhantomData,
                })),
                tls: CoreTlsState::new(tls_mod_id, tls_tp_offset, tls_info, tls_image),
                segments,
                finalizer: OnceCell::new(),
                user_data,
            }),
        })
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for ElfCore<D, Arch, R, Tls>
{
    /// Formats the ElfCore for debugging purposes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfCore")
            .field("path", &self.inner.path)
            .field("base", &format_args!("{}", self.base()))
            .field("tls", &self.tls())
            .finish()
    }
}

impl<D, Arch, R, Tls> Module<Arch, Tls> for ElfCore<D, Arch, R, Tls>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        ElfCore::name(self)
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        ElfCore::exports(self)
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        self.segments()
    }

    #[inline]
    fn tls(&self) -> ModuleTls {
        ElfCore::tls(self)
    }
}

impl<D, Arch, R, Tls> Module<Arch, Tls> for CoreInner<D, Arch, R, Tls>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        CoreInner::name(self)
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        &*self.exports
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        &self.segments
    }

    #[inline]
    fn tls(&self) -> ModuleTls {
        ModuleTls::new(self.tls.mod_id(), self.tls.tp_offset())
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
