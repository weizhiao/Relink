use crate::{
    ParsePhdrError, Result,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, SymbolTable},
    image::DynamicInfo,
    loader::{DynLifecycleHandler, LifecycleContext},
    relocation::{RelocAddr, RelocationArch},
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering, Weak},
    tls::{CoreTlsState, TlsDescArgs, TlsModuleId, TlsTpOffset},
};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt::Debug, ptr::NonNull};

/// Inner structure for ElfCore
#[repr(C)]
pub(crate) struct CoreInner<D = (), Arch: RelocationArch = crate::arch::NativeArch> {
    /// Indicates whether the component has been initialized
    pub(crate) is_init: AtomicBool,

    /// Full path of the ELF object
    pub(crate) name: String,

    /// ELF symbols table
    pub(crate) symtab: SymbolTable<Arch::Layout>,

    /// Finalization function
    pub(crate) fini: Option<fn()>,

    /// Finalization array of functions
    pub(crate) fini_array: Option<&'static [fn()]>,

    /// Custom finalization handler
    pub(crate) fini_handler: DynLifecycleHandler,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo<Arch>>>,

    /// TLS runtime state for the loaded object.
    pub(crate) tls: CoreTlsState,

    /// Memory segments
    pub(crate) segments: ElfSegments,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D, Arch: RelocationArch> Drop for CoreInner<D, Arch> {
    /// Executes finalization functions when the component is dropped
    fn drop(&mut self) {
        if self.is_init.load(Ordering::Relaxed) {
            self.fini_handler
                .call(&LifecycleContext::new(self.fini, self.fini_array));
        }
        self.tls.cleanup();
    }
}

/// A non-owning reference to an [`ElfCore`].
///
/// `ElfCoreRef` holds a weak reference to the shared core allocation. It is useful
/// when you want to avoid extending the lifetime of a loaded image unnecessarily
/// or need to detect when the image has been dropped.
#[derive(Clone)]
pub struct ElfCoreRef<D = (), Arch: RelocationArch = crate::arch::NativeArch> {
    /// Weak reference to the shared core allocation.
    inner: Weak<CoreInner<D, Arch>>,
}

impl<D, Arch: RelocationArch> ElfCoreRef<D, Arch> {
    /// Attempts to upgrade the weak pointer to an [`ElfCore`].
    ///
    /// # Returns
    /// * `Some(ElfCore)` - If the component is still alive and the upgrade is successful.
    /// * `None` - If the [`ElfCore`] has been dropped.
    pub fn upgrade(&self) -> Option<ElfCore<D, Arch>> {
        self.inner.upgrade().map(|inner| ElfCore { inner })
    }
}

/// Shared core state for a loaded ELF image.
///
/// `ElfCore` stores metadata, symbol tables, segments, TLS state, and lifecycle
/// handlers behind an [`Arc`]. Higher-level image wrappers delegate most common
/// operations to this type.
pub struct ElfCore<D = (), Arch: RelocationArch = crate::arch::NativeArch> {
    /// Shared reference to the inner component data.
    pub(crate) inner: Arc<CoreInner<D, Arch>>,
}

impl<D, Arch: RelocationArch> Clone for ElfCore<D, Arch> {
    /// Clones the [`ElfCore`], incrementing the internal reference count.
    fn clone(&self) -> Self {
        ElfCore {
            inner: Arc::clone(&self.inner),
        }
    }
}

// Safety: ModuleInner can be shared between threads
unsafe impl<D, Arch: RelocationArch> Sync for CoreInner<D, Arch> {}
// Safety: ModuleInner can be sent between threads
unsafe impl<D, Arch: RelocationArch> Send for CoreInner<D, Arch> {}

impl<D, Arch: RelocationArch> ElfCore<D, Arch> {
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
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch> {
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

    /// Gets the name (full path) of the ELF object
    #[inline]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Returns the DT_SONAME value when this core has dynamic metadata.
    #[inline]
    pub fn soname(&self) -> Option<&str> {
        self.inner
            .dynamic_info
            .as_ref()
            .and_then(|info| info.soname)
    }

    /// Gets the short name of the ELF object
    #[inline]
    pub fn short_name(&self) -> &str {
        let name = self.name();
        name.rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(name)
    }

    /// Gets the base address of the ELF object
    #[inline]
    pub fn base(&self) -> usize {
        self.inner.segments.base()
    }

    #[inline]
    pub(crate) fn base_addr(&self) -> RelocAddr {
        self.inner.segments.base_addr()
    }

    /// Gets the length of the bounding runtime span covered by mapped memory.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.inner.segments.mapped_len()
    }

    /// Returns the lowest runtime address covered by this image's mapped slices.
    #[inline]
    pub(crate) fn mapped_base(&self) -> usize {
        self.inner.segments.mapped_base()
    }

    /// Returns whether `addr` is inside one of this image's mapped slices.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        self.inner.segments.contains_addr(addr)
    }

    /// Returns whether the backing memory is one contiguous span with no gaps.
    #[inline]
    pub fn is_contiguous_mapping(&self) -> bool {
        self.inner.segments.is_contiguous_mapping()
    }

    /// Gets the symbol table
    #[inline]
    pub fn symtab(&self) -> &SymbolTable<Arch::Layout> {
        &self.inner.symtab
    }

    /// Gets a pointer to the dynamic section
    #[inline]
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn<Arch::Layout>>> {
        self.inner
            .dynamic_info
            .as_ref()
            .map(|info| info.dynamic_ptr)
    }

    /// Gets the EH frame header pointer
    #[inline]
    pub fn eh_frame_hdr(&self) -> Option<NonNull<u8>> {
        self.inner
            .dynamic_info
            .as_ref()
            .and_then(|info| info.eh_frame_hdr)
    }

    /// Gets the segments
    #[inline]
    pub(crate) fn segments(&self) -> &ElfSegments {
        &self.inner.segments
    }

    #[inline]
    pub(crate) fn segment_slice(&self, offset: usize, len: usize) -> &[u8] {
        self.segments().get_slice(offset, len)
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
    pub(crate) fn tls_get_addr(&self) -> RelocAddr {
        self.inner.tls.tls_get_addr()
    }

    /// Set the TLS descriptor arguments (used for dynamic relocation)
    /// # Safety
    /// This should only be called during the relocation process
    pub(crate) unsafe fn set_tls_desc_args(&self, args: TlsDescArgs) {
        let inner = Arc::as_ptr(&self.inner) as *mut CoreInner<D, Arch>;
        unsafe {
            (*inner).tls.set_desc_args(args);
        }
    }

    /// Creates an ElfCore from raw components
    pub(super) unsafe fn from_raw(
        name: String,
        base: usize,
        dynamic_ptr: *const ElfDyn<Arch::Layout>,
        phdrs: Vec<ElfPhdr<Arch::Layout>>,
        eh_frame_hdr: Option<NonNull<u8>>,
        mut segments: ElfSegments,
        tls_mod_id: Option<TlsModuleId>,
        tls_tp_offset: Option<TlsTpOffset>,
        tls_get_addr: RelocAddr,
        tls_unregister: fn(TlsModuleId),
        user_data: D,
    ) -> Result<Self> {
        if dynamic_ptr.is_null() {
            return Err(ParsePhdrError::MissingDynamicSection.into());
        }

        segments.set_base(base);
        let dynamic = ElfDynamic::<Arch>::new(dynamic_ptr, &segments)?;
        let symtab = SymbolTable::from_dynamic(&dynamic);
        let soname = dynamic
            .soname_off
            .map(|soname_off| symtab.strtab().get_str(soname_off.get()));
        Ok(Self {
            inner: Arc::new(CoreInner {
                name,
                is_init: AtomicBool::new(true),
                symtab,
                dynamic_info: Some(Arc::new(DynamicInfo {
                    eh_frame_hdr,
                    dynamic_ptr: unsafe { NonNull::new_unchecked(dynamic_ptr.cast_mut()) },
                    phdrs: ElfPhdrs::Vec(phdrs),
                    soname,
                    #[cfg(feature = "lazy-binding")]
                    lazy: crate::image::LazyBindingInfo::new(dynamic.pltrel),
                })),
                tls: CoreTlsState::new(tls_mod_id, tls_tp_offset, tls_get_addr, tls_unregister),
                segments,
                fini: None,
                fini_array: None,
                fini_handler: Arc::new(Box::new(|_: &LifecycleContext| {})),
                user_data,
            }),
        })
    }
}

impl<D, Arch: RelocationArch> Debug for ElfCore<D, Arch> {
    /// Formats the ElfCore for debugging purposes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfCore")
            .field("name", &self.inner.name)
            .field("base", &format_args!("0x{:x}", self.base()))
            .field("mapped_len", &self.mapped_len())
            .field("tls_mod_id", &self.tls_mod_id())
            .finish()
    }
}
