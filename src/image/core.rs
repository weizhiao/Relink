//! Shared core state for loaded ELF images.
//!
//! The types in this module back the public image wrappers exposed from
//! [`crate::image`]. They store metadata, symbol tables, mapped segments,
//! lifecycle handlers, TLS state, and dependency ownership.

use crate::{
    ParsePhdrError, Result,
    arch::ArchKind,
    elf::{
        ElfDyn, ElfDynamic, ElfDynamicTag, ElfPhdr, ElfPhdrs, ElfProgramType, SymbolInfo,
        SymbolTable,
    },
    image::{DynamicInfo, Symbol},
    loader::{DynLifecycleHandler, LifecycleContext},
    relocation::{RelocAddr, RelocationArch, SymDef},
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering, Weak},
    tls::{CoreTlsState, TlsDescArgs, TlsInfo, TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::{ffi::c_void, fmt::Debug, marker::PhantomData, ptr::NonNull};
use elf::abi::DF_STATIC_TLS;

/// A fully loaded and relocated ELF module with retained dependencies.
///
/// This is the common loaded representation used by relocated dylibs, dynamic
/// [`crate::image::LoadedExec`] values, and loaded object-file images.
pub struct LoadedCore<D: 'static = (), Arch: RelocationArch = crate::arch::NativeArch> {
    pub(crate) core: ElfCore<D, Arch>,
    pub(crate) deps: Arc<[LoadedCore<D, Arch>]>,
}

impl<D: 'static, Arch: RelocationArch> Debug for LoadedCore<D, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedCore")
            .field("name", &self.core.name())
            .field("base", &format_args!("0x{:x}", self.core.base()))
            .field(
                "deps",
                &self
                    .deps
                    .iter()
                    .map(|d| d.name())
                    .collect::<alloc::vec::Vec<_>>(),
            )
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch> Clone for LoadedCore<D, Arch> {
    /// Clones the [`LoadedCore`], incrementing the reference count of its core and dependencies.
    fn clone(&self) -> Self {
        LoadedCore {
            core: self.core.clone(),
            deps: Arc::clone(&self.deps),
        }
    }
}

impl<D: 'static, Arch: RelocationArch> From<&LoadedCore<D, Arch>> for LoadedCore<D, Arch> {
    #[inline]
    fn from(module: &LoadedCore<D, Arch>) -> Self {
        module.clone()
    }
}

impl<D: 'static, Arch: RelocationArch> LoadedCore<D, Arch> {
    /// Wraps an [`ElfCore`] into a [`LoadedCore`] with no dependencies.
    ///
    /// # Safety
    ///
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core(core: ElfCore<D, Arch>) -> Self {
        LoadedCore {
            core,
            deps: Arc::from([]),
        }
    }

    /// Returns a slice of the libraries this module depends on.
    pub fn deps(&self) -> &[LoadedCore<D, Arch>] {
        &self.deps
    }

    /// Returns the relocation backend used by this loaded module.
    #[inline]
    pub const fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    /// Returns the name (full path) of the ELF object.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the DT_SONAME value when this is a dynamic object.
    #[inline]
    pub fn soname(&self) -> Option<&str> {
        self.core.soname()
    }

    /// Returns the short name of the ELF object.
    #[inline]
    pub fn short_name(&self) -> &str {
        self.core.short_name()
    }

    /// Returns the base address of the ELF object.
    #[inline]
    pub fn base(&self) -> usize {
        self.core.base()
    }

    /// Gets the length of the bounding runtime span covered by mapped memory.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.core.mapped_len()
    }

    /// Returns whether `addr` is inside one of this module's mapped slices.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        self.core.contains_addr(addr)
    }

    /// Returns whether the backing memory is one contiguous span with no gaps.
    #[inline]
    pub fn is_contiguous_mapping(&self) -> bool {
        self.core.is_contiguous_mapping()
    }

    /// Gets the user-defined data associated with the ELF object
    #[inline]
    pub fn user_data(&self) -> &D {
        self.core.user_data()
    }

    /// Returns a mutable reference to the user-defined data.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        self.core.user_data_mut()
    }

    /// Returns whether the ELF object has been initialized.
    #[inline]
    pub fn is_init(&self) -> bool {
        self.core.is_init()
    }

    /// Returns the program headers of the ELF object.
    #[inline]
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        self.core.phdrs()
    }

    /// Gets the EH frame header pointer
    #[inline]
    pub fn eh_frame_hdr(&self) -> Option<NonNull<u8>> {
        self.core.eh_frame_hdr()
    }

    /// Gets a pointer to the dynamic section
    #[inline]
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn<Arch::Layout>>> {
        self.core.dynamic_ptr()
    }

    /// Gets the number of strong references to the ELF object
    #[inline]
    pub fn strong_count(&self) -> usize {
        self.core.strong_count()
    }

    /// Gets the number of weak references to the ELF object
    #[inline]
    pub fn weak_count(&self) -> usize {
        self.core.weak_count()
    }

    /// Creates a weak reference to this ELF core.
    #[inline]
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch> {
        self.core.downgrade()
    }

    /// Gets the TLS module ID of the ELF object
    #[inline]
    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        self.core.tls_mod_id()
    }

    /// Gets the TLS thread pointer offset of the ELF object
    #[inline]
    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        self.core.tls_tp_offset()
    }

    /// Creates a [`LoadedCore`] from an [`ElfCore`] and its explicit dependencies.
    ///
    /// # Safety
    /// The caller must ensure the ELF object has been properly relocated.
    ///
    /// # Arguments
    /// * `core` - The [`ElfCore`] to wrap.
    /// * `deps` - A vector of dependencies.
    #[inline]
    pub unsafe fn from_core_deps(core: ElfCore<D, Arch>, deps: Arc<[LoadedCore<D, Arch>]>) -> Self {
        LoadedCore { core, deps }
    }

    /// Returns a reference to the underlying [`ElfCore`].
    ///
    /// # Safety
    /// Lifecycle information is lost, so the dependencies of the current
    /// loaded object can be dropped too early if this reference is used carelessly.
    #[inline]
    pub unsafe fn core_ref(&self) -> &ElfCore<D, Arch> {
        &self.core
    }

    /// Creates a new [`LoadedCore`] from raw parts without validation.
    ///
    /// # Safety
    /// The caller must ensure that the provided metadata, segments, and TLS values
    /// describe a valid loaded ELF image.
    ///
    /// # Arguments
    /// * `name` - The name of the ELF file
    /// * `phdrs` - The program headers
    /// * `memory` - The mapped memory (pointer and length)
    /// * `munmap` - Function to unmap the memory
    /// * `tls_tp_offset` - TLS thread pointer offset
    /// * `user_data` - User-defined data to associate with the ELF
    ///
    /// # Returns
    /// A new [`LoadedCore`] instance
    #[inline]
    pub unsafe fn new_unchecked<Tls: TlsResolver>(
        name: String,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        memory: (*mut c_void, usize),
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
        tls_tp_offset: Option<TlsTpOffset>,
        user_data: D,
    ) -> Result<Self> {
        let segments = ElfSegments::new(memory.0, memory.1, munmap);
        let base = segments.base();
        let mut tls_mod_id = None;
        let mut actual_tls_tp_offset = tls_tp_offset;

        let mut dynamic_ptr = core::ptr::null();
        let mut eh_frame_hdr = None;
        let mut tls_phdr = None;
        let phdrs = phdrs.into();

        for phdr in &phdrs {
            match phdr.program_type() {
                ElfProgramType::DYNAMIC => {
                    dynamic_ptr = base.wrapping_add(phdr.p_vaddr()) as *const ElfDyn<Arch::Layout>;
                }
                ElfProgramType::GNU_EH_FRAME => {
                    eh_frame_hdr = NonNull::new(base.wrapping_add(phdr.p_vaddr()) as *mut u8);
                }
                ElfProgramType::TLS => {
                    tls_phdr = Some(phdr);
                }
                _ => {}
            }
        }

        if let Some(phdr) = tls_phdr {
            unsafe {
                let template = core::slice::from_raw_parts(
                    base.wrapping_add(phdr.p_vaddr()) as *const u8,
                    phdr.p_filesz(),
                );
                let info = TlsInfo::new(phdr, core::mem::transmute(template));

                let mut static_tls = actual_tls_tp_offset.is_some();
                if !static_tls && !dynamic_ptr.is_null() {
                    let mut cur = dynamic_ptr;
                    loop {
                        let dynamic = &*cur;
                        let tag = dynamic.tag();
                        if tag == ElfDynamicTag::NULL {
                            break;
                        }
                        if tag == ElfDynamicTag::FLAGS
                            && dynamic.value() & DF_STATIC_TLS as usize != 0
                        {
                            static_tls = true;
                            break;
                        }
                        cur = cur.add(1);
                    }
                }

                // The Tls::register will register the TLS module and return the ID.
                if static_tls {
                    if let Some(offset) = actual_tls_tp_offset {
                        tls_mod_id = Some(Tls::add_static_tls(&info, offset)?);
                    } else {
                        let (mid, offset) = Tls::register_static(&info)?;
                        tls_mod_id = Some(mid);
                        actual_tls_tp_offset = Some(offset);
                    }
                } else {
                    tls_mod_id = Some(Tls::register(&info)?);
                }
            }
        }
        Ok(Self {
            core: unsafe {
                ElfCore::from_raw(
                    name,
                    base,
                    dynamic_ptr,
                    phdrs,
                    eh_frame_hdr,
                    segments,
                    tls_mod_id,
                    actual_tls_tp_offset,
                    RelocAddr::from_ptr(Tls::tls_get_addr as *const ()),
                    Tls::unregister,
                    user_data,
                )
            }?,
            deps: Arc::from([]),
        })
    }

    /// Gets the symbol table
    pub fn symtab(&self) -> &SymbolTable<Arch::Layout> {
        &self.core.symtab()
    }

    /// Gets a pointer to a function or static variable by symbol name
    ///
    /// The symbol is interpreted as-is; no mangling is done. This means
    /// that symbols like `x::y` are most likely invalid.
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function
    /// or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader};
    /// # let mut loader = Loader::new();
    /// # let lib = loader
    /// #     .load_dylib(ElfBinary::new("target/liba.so", &[]))
    /// #        .unwrap().relocator().relocate().unwrap();
    /// unsafe {
    ///     let awesome_function = lib.get::<unsafe extern "C" fn(f64) -> f64>("awesome_function").unwrap();
    ///     awesome_function(0.42);
    /// }
    /// ```
    ///
    /// A static variable may also be loaded and inspected:
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader};
    /// # let mut loader = Loader::new();
    /// # let lib = loader
    /// #     .load_dylib(ElfBinary::new("target/liba.so", &[]))
    /// #        .unwrap().relocator().relocate().unwrap();
    /// unsafe {
    ///     let awesome_variable = lib.get::<*mut f64>("awesome_variable").unwrap();
    ///     **awesome_variable = 42.0;
    /// };
    /// ```
    ///
    /// # Arguments
    /// * `name` - The name of the symbol to look up
    ///
    /// # Returns
    /// * `Some(symbol)` - If the symbol is found
    /// * `None` - If the symbol is not found
    #[inline]
    pub unsafe fn get<'lib, T>(&'lib self, name: &str) -> Option<Symbol<'lib, T>> {
        let syminfo = SymbolInfo::from_str(name, None);
        let mut precompute = syminfo.precompute();
        self.symtab()
            .lookup_filter(&syminfo, &mut precompute)
            .map(|sym| Symbol {
                ptr: SymDef {
                    sym: Some(sym),
                    lib: unsafe { self.core_ref() },
                }
                .convert()
                .as_mut_ptr(),
                pd: PhantomData,
            })
    }

    /// Load a versioned symbol from the ELF object
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function
    /// or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{Loader, input::ElfFile};
    /// # let mut loader = Loader::new();
    /// # let lib = loader
    /// #     .load_dylib(ElfFile::from_path("target/liba.so").unwrap())
    /// #        .unwrap().relocator().relocate().unwrap();;
    /// let symbol = unsafe { lib.get_version::<fn()>("function_name", "1.0").unwrap() };
    /// ```
    ///
    /// # Arguments
    /// * `name` - The name of the symbol to look up
    /// * `version` - The version of the symbol to look up
    ///
    /// # Returns
    /// * `Some(symbol)` - If the symbol is found
    /// * `None` - If the symbol is not found
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<'lib, T>(
        &'lib self,
        name: &str,
        version: &str,
    ) -> Option<Symbol<'lib, T>> {
        let syminfo = SymbolInfo::from_str(name, Some(version));
        let mut precompute = syminfo.precompute();
        self.symtab()
            .lookup_filter(&syminfo, &mut precompute)
            .map(|sym| Symbol {
                ptr: SymDef {
                    sym: Some(sym),
                    lib: unsafe { self.core_ref() },
                }
                .convert()
                .as_mut_ptr(),
                pd: PhantomData,
            })
    }
}

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
    unsafe fn from_raw(
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
                    lazy: super::LazyBindingInfo::new(dynamic.pltrel),
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
