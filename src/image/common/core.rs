//! ELF file format handling
//!
//! This module provides the core data structures and functionality for working
//! with ELF files in various stages of processing: from raw ELF files to
//! relocated and loaded libraries or executables.

use crate::{
    Result,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, SymbolInfo, SymbolTable},
    image::{Symbol, common::DynamicInfo},
    loader::{DynLifecycleHandler, LifecycleContext},
    relocation::SymDef,
    segment::ElfSegments,
    sync::{Arc, AtomicBool, Ordering, Weak},
    tls::{TlsDescDynamicArg, TlsInfo, TlsResolver},
};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::{ffi::c_void, fmt::Debug, marker::PhantomData, ptr::NonNull};
use elf::abi::{DF_STATIC_TLS, DT_FLAGS, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_TLS};

/// A fully loaded and relocated ELF module.
///
/// This structure represents an ELF object (executable, shared library, or relocatable object)
/// that has been mapped into memory and had its relocations performed.
///
/// It maintains an `Arc` reference to its dependencies to ensure that required
/// libraries remain in memory as long as this module is alive.
pub struct LoadedCore<D = ()> {
    pub(crate) core: ElfCore<D>,
    pub(crate) deps: Arc<[LoadedCore<D>]>,
}

impl<D> Debug for LoadedCore<D> {
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

impl<D> Clone for LoadedCore<D> {
    /// Clones the [`LoadedCore`], incrementing the reference count of its core and dependencies.
    fn clone(&self) -> Self {
        LoadedCore {
            core: self.core.clone(),
            deps: Arc::clone(&self.deps),
        }
    }
}

impl<D> LoadedCore<D> {
    /// Wraps an [`ElfCore`] into a [`LoadedCore`] with no dependencies.
    ///
    /// # Safety
    /// The caller must ensure the ELF object has been properly relocated.
    ///
    /// # Arguments
    /// * `core` - The [`ElfCore`] to wrap.
    #[inline]
    pub unsafe fn from_core(core: ElfCore<D>) -> Self {
        LoadedCore {
            core,
            deps: Arc::from([]),
        }
    }

    /// Returns a slice of the libraries this module depends on.
    pub fn deps(&self) -> &[LoadedCore<D>] {
        &self.deps
    }

    /// Gets the name (full path) of the ELF object
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Gets the short name of the ELF object
    #[inline]
    pub fn short_name(&self) -> &str {
        self.core.short_name()
    }

    /// Gets the base address of the ELF object
    #[inline]
    pub fn base(&self) -> usize {
        self.core.base()
    }

    /// Gets the memory length of the ELF object map
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.core.mapped_len()
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
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
        self.core.phdrs()
    }

    /// Gets the EH frame header pointer
    #[inline]
    pub fn eh_frame_hdr(&self) -> Option<NonNull<u8>> {
        self.core.eh_frame_hdr()
    }

    /// Gets a pointer to the dynamic section
    #[inline]
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn>> {
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
    pub fn downgrade(&self) -> ElfCoreRef<D> {
        self.core.downgrade()
    }

    /// Gets the TLS module ID of the ELF object
    #[inline]
    pub fn tls_mod_id(&self) -> Option<usize> {
        self.core.tls_mod_id()
    }

    /// Gets the TLS thread pointer offset of the ELF object
    #[inline]
    pub fn tls_tp_offset(&self) -> Option<isize> {
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
    pub unsafe fn from_core_deps(core: ElfCore<D>, deps: Arc<[LoadedCore<D>]>) -> Self {
        LoadedCore { core, deps }
    }

    /// Gets the core component reference of the ELF object
    ///
    /// # Safety
    /// Lifecycle information is lost, and the dependencies of the current
    /// ELF object can be prematurely deallocated, which can cause serious problems.
    ///
    /// # Returns
    /// A reference to the ElfCore
    #[inline]
    pub unsafe fn core_ref(&self) -> &ElfCore<D> {
        &self.core
    }

    /// Creates a new LoadedModule instance without validation
    ///
    /// # Safety
    /// The caller needs to ensure that the parameters passed in come
    /// from a valid dynamic library.
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
    /// A new LoadedCore instance
    #[inline]
    pub unsafe fn new_unchecked<Tls: TlsResolver>(
        name: String,
        phdrs: &'static [ElfPhdr],
        memory: (*mut c_void, usize),
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
        tls_tp_offset: Option<isize>,
        user_data: D,
    ) -> Result<Self> {
        let segments = ElfSegments::new(memory.0, memory.1, munmap);
        let base = segments.base();
        let mut tls_mod_id = None;
        let mut actual_tls_tp_offset = tls_tp_offset;

        let mut dynamic_ptr = core::ptr::null();
        let mut eh_frame_hdr = None;
        let mut tls_phdr = None;

        for phdr in phdrs {
            match phdr.p_type {
                PT_DYNAMIC => {
                    dynamic_ptr = base.wrapping_add(phdr.p_vaddr as usize) as *const ElfDyn;
                }
                PT_GNU_EH_FRAME => {
                    eh_frame_hdr =
                        NonNull::new(base.wrapping_add(phdr.p_vaddr as usize) as *mut u8);
                }
                PT_TLS => {
                    tls_phdr = Some(phdr);
                }
                _ => {}
            }
        }

        if let Some(phdr) = tls_phdr {
            unsafe {
                let template = core::slice::from_raw_parts(
                    base.wrapping_add(phdr.p_vaddr as usize) as *const u8,
                    phdr.p_filesz as usize,
                );
                let info = TlsInfo::new(phdr, core::mem::transmute(template));

                let mut static_tls = actual_tls_tp_offset.is_some();
                if !static_tls && !dynamic_ptr.is_null() {
                    let mut cur = dynamic_ptr;
                    while (*cur).d_tag != 0 {
                        if (*cur).d_tag as u64 == DT_FLAGS as u64 {
                            if (*cur).d_un as usize & DF_STATIC_TLS as usize != 0 {
                                static_tls = true;
                                break;
                            }
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
                    Tls::unregister,
                    user_data,
                )
            },
            deps: Arc::from([]),
        })
    }

    /// Gets the symbol table
    pub fn symtab(&self) -> &SymbolTable {
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
                .convert() as _,
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
    /// # use elf_loader::{ElfFile, Symbol, mmap::DefaultMmap, Loader};
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
                .convert() as _,
                pd: PhantomData,
            })
    }
}

/// Inner structure for ElfCore
#[repr(C)]
pub(crate) struct CoreInner<D = ()> {
    /// Indicates whether the component has been initialized
    pub(crate) is_init: AtomicBool,

    /// Full path of the ELF object
    pub(crate) name: String,

    /// ELF symbols table
    pub(crate) symtab: SymbolTable,

    /// Finalization function
    pub(crate) fini: Option<fn()>,

    /// Finalization array of functions
    pub(crate) fini_array: Option<&'static [fn()]>,

    /// Custom finalization handler
    pub(crate) fini_handler: DynLifecycleHandler,

    /// Dynamic information
    pub(crate) dynamic_info: Option<Arc<DynamicInfo>>,

    /// TLS module ID
    pub(crate) tls_mod_id: Option<usize>,

    /// TLS thread pointer offset (for static TLS)
    pub(crate) tls_tp_offset: Option<isize>,

    /// TLS resolver unregister function
    pub(crate) tls_unregister: fn(usize),

    /// TLS descriptor arguments (for TLSDESC)
    pub(crate) tls_desc_args: Box<[Box<TlsDescDynamicArg>]>,

    /// Memory segments
    pub(crate) segments: ElfSegments,

    /// User-defined data
    pub(crate) user_data: D,
}

impl<D> Drop for CoreInner<D> {
    /// Executes finalization functions when the component is dropped
    fn drop(&mut self) {
        if self.is_init.load(Ordering::Relaxed) {
            self.fini_handler
                .call(&LifecycleContext::new(self.fini, self.fini_array));
        }
        if let Some(mod_id) = self.tls_mod_id {
            (self.tls_unregister)(mod_id);
        }
    }
}

/// A non-owning reference to a [`ElfCore`].
///
/// `ElfCoreRef` holds a weak reference to the managed allocation of a
/// [`ElfCore`]. It can be used to avoid circular dependencies or to
/// check if the component is still alive.
#[derive(Clone)]
pub struct ElfCoreRef<D = ()> {
    /// Weak reference to the [`ModuleInner`].
    inner: Weak<CoreInner<D>>,
}

impl<D> ElfCoreRef<D> {
    /// Attempts to upgrade the weak pointer to an [`ElfCore`].
    ///
    /// # Returns
    /// * `Some(ElfCore)` - If the component is still alive and the upgrade is successful.
    /// * `None` - If the [`ElfCore`] has been dropped.
    pub fn upgrade(&self) -> Option<ElfCore<D>> {
        self.inner.upgrade().map(|inner| ElfCore { inner })
    }
}

/// The core part of an ELF object.
///
/// This structure represents the core data of an ELF object, including
/// its metadata, symbols, segments, and other essential information.
/// It uses an [`Arc`] internally to manage the lifetime of the underlying data
/// and enable shared ownership.
pub struct ElfCore<D = ()> {
    /// Shared reference to the inner component data.
    pub(crate) inner: Arc<CoreInner<D>>,
}

impl<D> Clone for ElfCore<D> {
    /// Clones the [`ElfCore`], incrementing the internal reference count.
    fn clone(&self) -> Self {
        ElfCore {
            inner: Arc::clone(&self.inner),
        }
    }
}

// Safety: ModuleInner can be shared between threads
unsafe impl<D> Sync for CoreInner<D> {}
// Safety: ModuleInner can be sent between threads
unsafe impl<D> Send for CoreInner<D> {}

impl<D> ElfCore<D> {
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
    pub fn downgrade(&self) -> ElfCoreRef<D> {
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
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
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

    /// Gets the memory length of the ELF object map
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.inner.segments.len()
    }

    /// Gets the symbol table
    #[inline]
    pub fn symtab(&self) -> &SymbolTable {
        &self.inner.symtab
    }

    /// Gets a pointer to the dynamic section
    #[inline]
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn>> {
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

    /// Gets the TLS module ID of the ELF object
    #[inline]
    pub fn tls_mod_id(&self) -> Option<usize> {
        self.inner.tls_mod_id
    }

    /// Gets the TLS thread pointer offset of the ELF object
    #[inline]
    pub fn tls_tp_offset(&self) -> Option<isize> {
        self.inner.tls_tp_offset
    }

    /// Set the TLS descriptor arguments (used for dynamic relocation)
    /// # Safety
    /// This should only be called during the relocation process
    pub(crate) unsafe fn set_tls_desc_args(&self, args: Vec<Box<TlsDescDynamicArg>>) {
        let inner = Arc::as_ptr(&self.inner) as *mut CoreInner<D>;
        unsafe {
            (*inner).tls_desc_args = args.into_boxed_slice();
        }
    }

    /// Creates an ElfCore from raw components
    unsafe fn from_raw(
        name: String,
        base: usize,
        dynamic_ptr: *const ElfDyn,
        phdrs: &'static [ElfPhdr],
        eh_frame_hdr: Option<NonNull<u8>>,
        mut segments: ElfSegments,
        tls_mod_id: Option<usize>,
        tls_tp_offset: Option<isize>,
        tls_unregister: fn(usize),
        user_data: D,
    ) -> Self {
        segments.offset = (segments.memory as usize).wrapping_sub(base);
        let dynamic = ElfDynamic::new(dynamic_ptr, &segments).unwrap();
        Self {
            inner: Arc::new(CoreInner {
                name,
                is_init: AtomicBool::new(true),
                symtab: SymbolTable::from_dynamic(&dynamic),
                dynamic_info: Some(Arc::new(DynamicInfo {
                    eh_frame_hdr,
                    dynamic_ptr: NonNull::new(dynamic.dyn_ptr as _).unwrap(),
                    pltrel: dynamic
                        .pltrel
                        .and_then(|plt| NonNull::new(plt.as_ptr() as *mut _)),
                    phdrs: ElfPhdrs::Mmap(phdrs),
                    lazy_scope: None,
                })),
                tls_mod_id,
                tls_tp_offset,
                tls_unregister,
                tls_desc_args: Box::new([]),
                segments,
                fini: None,
                fini_array: None,
                fini_handler: Arc::new(Box::new(|_: &LifecycleContext| {})),
                user_data,
            }),
        }
    }
}

impl<D> Debug for ElfCore<D> {
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
