use crate::{
    LoadHook, Result,
    elf::{Dyn, ElfDynamic, ElfPhdr, ElfPhdrs, ElfRelType, SymbolTable},
    image::{ElfCore, ImageBuilder, common::CoreInner},
    loader::FnHandler,
    os::Mmap,
    relocation::{DynamicRelocation, SymbolLookup},
    segment::{ELFRelro, ElfSegments},
    tls::TlsResolver,
};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    cell::Cell,
    ffi::CStr,
    ops::{Deref, DerefMut},
    ptr::{NonNull, null},
    sync::atomic::AtomicBool,
};

#[cfg(not(feature = "portable-atomic"))]
use alloc::sync::Arc;
#[cfg(feature = "portable-atomic")]
use portable_atomic_util::Arc;

pub(crate) struct DynamicInfo {
    pub(crate) dynamic_ptr: NonNull<Dyn>,
    pub(crate) pltrel: Option<NonNull<ElfRelType>>,
    pub(crate) phdrs: ElfPhdrs,
    /// Lazy binding scope for symbol resolution during lazy binding
    /// Stored as trait object for type erasure of different SymbolLookup implementations
    pub(crate) lazy_scope: Option<Arc<dyn SymbolLookup>>,
}

/// Extra data associated with ELF objects during relocation
///
/// This structure holds additional data that is needed during the relocation
/// process but is not part of the core ELF object structure.
struct ElfExtraData {
    /// Indicates whether lazy binding is enabled for this object
    lazy: bool,

    /// Pointer to the Global Offset Table (.got.plt section)
    got_plt: Option<NonNull<usize>>,

    /// Dynamic relocation information (rela.dyn and rela.plt)
    relocation: DynamicRelocation,

    /// GNU_RELRO segment information for memory protection
    relro: Option<ELFRelro>,

    /// Initialization function to be called after relocation
    init: Box<dyn Fn()>,

    /// DT_RPATH value from the dynamic section
    rpath: Option<&'static str>,

    /// DT_RUNPATH value from the dynamic section
    runpath: Option<&'static str>,

    /// List of needed library names from the dynamic section
    needed_libs: Box<[&'static str]>,

    /// Function to get TLS address
    tls_get_addr: extern "C" fn(*const crate::tls::TlsIndex) -> *mut u8,
}

/// Data structure used during lazy parsing of ELF objects
///
/// This structure holds the data needed to initialize an ELF object
/// during the relocation process.
struct LazyData<D> {
    /// Core component containing the basic ELF object information
    module: ElfCore<D>,
    /// Extra data needed for relocation
    extra: ElfExtraData,
}

/// State of an ELF object during the loading/relocation process
///
/// This enum represents the different states an ELF object can be in
/// during the loading and relocation process.
enum State<D> {
    /// Initial empty state
    Empty,

    /// Uninitialized state with all necessary data to perform initialization
    Uninit {
        /// Program headers
        phdrs: ElfPhdrs,

        /// Initialization function handler
        init_handler: FnHandler,

        /// Finalization function handler
        fini_handler: FnHandler,

        /// Name of the ELF file
        name: String,

        /// Pointer to the dynamic section
        dynamic_ptr: NonNull<Dyn>,

        /// Memory segments
        segments: ElfSegments,

        /// GNU_RELRO segment information
        relro: Option<ELFRelro>,

        /// TLS module ID
        tls_mod_id: Option<usize>,

        /// TLS thread pointer offset
        tls_tp_offset: Option<isize>,

        /// TLS resolver unregister function
        tls_unregister: fn(usize),

        /// TLS get addr function
        tls_get_addr: extern "C" fn(*const crate::tls::TlsIndex) -> *mut u8,

        /// User-defined data
        user_data: D,
    },

    /// Initialized state with all data ready for relocation
    Init(LazyData<D>),
}

impl<D> State<D> {
    /// Initialize the state by parsing the dynamic section and preparing relocation data
    ///
    /// This method processes the dynamic section of the ELF file and prepares
    /// all the data needed for relocation.
    ///
    /// # Returns
    /// The initialized state
    fn init(self) -> Self {
        let lazy_data = match self {
            State::Uninit {
                name,
                dynamic_ptr,
                segments,
                relro,
                tls_mod_id,
                tls_tp_offset,
                tls_unregister,
                tls_get_addr,
                user_data,
                init_handler,
                fini_handler,
                phdrs,
            } => {
                // If we have a dynamic section, parse it and prepare relocation data

                let dynamic = ElfDynamic::new(dynamic_ptr.as_ptr(), &segments).unwrap();
                let relocation = DynamicRelocation::new(
                    dynamic.pltrel,
                    dynamic.dynrel,
                    dynamic.relr,
                    dynamic.rel_count,
                );

                // Create symbol table from dynamic section
                let symtab = SymbolTable::from_dynamic(&dynamic);

                // Collect needed library names
                let needed_libs: Vec<&'static str> = dynamic
                    .needed_libs
                    .iter()
                    .map(|needed_lib| symtab.strtab().get_str(needed_lib.get()))
                    .collect();

                // Create the lazy data structure
                LazyData {
                    extra: ElfExtraData {
                        // Determine if lazy binding should be enabled
                        lazy: !dynamic.bind_now,

                        // Store GNU_RELRO segment information
                        relro,

                        // Store relocation information
                        relocation,

                        // Create initialization function
                        init: Box::new(move || {
                            init_handler(dynamic.init_fn, dynamic.init_array_fn)
                        }),

                        // Store GOT pointer
                        got_plt: dynamic.got_plt,

                        // Store RPATH value
                        rpath: dynamic
                            .rpath_off
                            .map(|rpath_off| symtab.strtab().get_str(rpath_off.get())),

                        // Store needed library names
                        needed_libs: needed_libs.into_boxed_slice(),

                        // Store RUNPATH value
                        runpath: dynamic
                            .runpath_off
                            .map(|runpath_off| symtab.strtab().get_str(runpath_off.get())),

                        // Store TLS get addr function
                        tls_get_addr,
                    },
                    module: ElfCore {
                        inner: Arc::new(CoreInner {
                            is_init: AtomicBool::new(false),
                            name,
                            symtab,
                            fini: dynamic.fini_fn,
                            fini_array: dynamic.fini_array_fn,
                            fini_handler,
                            user_data,
                            dynamic_info: Some(Arc::new(DynamicInfo {
                                dynamic_ptr: NonNull::new(dynamic.dyn_ptr as _).unwrap(),
                                pltrel: NonNull::new(
                                    dynamic.pltrel.map_or(null(), |plt| plt.as_ptr()) as _,
                                ),
                                phdrs,
                                lazy_scope: None,
                            })),
                            tls_mod_id,
                            tls_tp_offset,
                            tls_unregister,
                            segments,
                        }),
                    },
                }
            }
            State::Empty | State::Init(_) => unreachable!(),
        };
        State::Init(lazy_data)
    }
}

/// Lazy parser for ELF object data
///
/// This structure implements lazy parsing of ELF object data, only
/// initializing the data when it's actually needed.
struct LazyParse<D> {
    /// The current state of the parser
    state: Cell<State<D>>,
}

impl<D> LazyParse<D> {
    /// Force initialization of the parser and return a reference to the lazy data
    ///
    /// This method ensures that the ELF object data is initialized and returns
    /// a reference to it. If the data is already initialized, it returns
    /// immediately. Otherwise, it performs the initialization.
    ///
    /// # Returns
    /// A reference to the initialized lazy data
    fn force(&self) -> &LazyData<D> {
        // Fast path - if already initialized, return immediately
        if let State::Init(lazy_data) = unsafe { &*self.state.as_ptr() } {
            return lazy_data;
        }

        // Initialize the data
        self.state.set(self.state.replace(State::Empty).init());

        // Return the initialized data
        match unsafe { &*self.state.as_ptr() } {
            State::Empty | State::Uninit { .. } => unreachable!(),
            State::Init(lazy_data) => lazy_data,
        }
    }

    /// Force initialization of the parser and return a mutable reference to the lazy data
    ///
    /// This method ensures that the ELF object data is initialized and returns
    /// a mutable reference to it. If the data is already initialized, it returns
    /// immediately. Otherwise, it performs the initialization.
    ///
    /// # Returns
    /// A mutable reference to the initialized lazy data
    fn force_mut(&mut self) -> &mut LazyData<D> {
        // Fast path - if already initialized, return immediately
        // 快路径加速
        if let State::Init(lazy_data) = self.state.get_mut() {
            return unsafe { core::mem::transmute(lazy_data) };
        }

        // Initialize the data
        self.state.set(self.state.replace(State::Empty).init());

        // Return the initialized data
        match unsafe { &mut *self.state.as_ptr() } {
            State::Empty | State::Uninit { .. } => unreachable!(),
            State::Init(lazy_data) => lazy_data,
        }
    }
}

impl<D> Deref for LazyParse<D> {
    type Target = LazyData<D>;

    /// Dereference to the lazy data
    ///
    /// This implementation allows direct access to the lazy data through
    /// the LazyParse wrapper.
    #[inline]
    fn deref(&self) -> &LazyData<D> {
        self.force()
    }
}

impl<D> DerefMut for LazyParse<D> {
    /// Mutable dereference to the lazy data
    ///
    /// This implementation allows direct mutable access to the lazy data
    /// through the LazyParse wrapper.
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.force_mut()
    }
}

/// A common part of relocated ELF objects.
///
/// This structure represents the common components shared by all relocated
/// ELF objects, whether they are dynamic libraries or executables.
/// It contains basic information like entry point, name, and program headers,
/// as well as lazily parsed data required for relocation and symbol lookup.
pub(crate) struct DynamicImage<D>
where
    D: 'static,
{
    /// Entry point of the ELF object.
    entry: usize,
    /// PT_INTERP segment value (interpreter path).
    interp: Option<&'static str>,
    /// Name of the ELF file.
    name: &'static str,
    /// Program headers.
    phdrs: ElfPhdrs,
    /// Data parsed lazily.
    data: LazyParse<D>,
}

impl<D> DynamicImage<D> {
    /// Gets the entry point of the ELF object.
    #[inline]
    pub fn entry(&self) -> usize {
        self.entry
    }

    pub fn tls_mod_id(&self) -> Option<usize> {
        self.data.module.tls_mod_id()
    }

    /// Gets the TLS thread pointer offset
    pub fn tls_tp_offset(&self) -> Option<isize> {
        self.data.module.tls_tp_offset()
    }

    pub(crate) fn tls_get_addr(&self) -> extern "C" fn(*const crate::tls::TlsIndex) -> *mut u8 {
        self.data.extra.tls_get_addr
    }

    /// Gets the core component reference of the ELF object.
    #[inline]
    pub fn core_ref(&self) -> &ElfCore<D> {
        &self.data.module
    }

    /// Gets the core component of the ELF object.
    #[inline]
    pub fn core(&self) -> ElfCore<D> {
        self.core_ref().clone()
    }

    /// Converts this object into its core component.
    #[inline]
    pub fn into_core(self) -> ElfCore<D> {
        self.core()
    }

    /// Whether lazy binding is enabled for the current ELF object
    #[inline]
    pub fn is_lazy(&self) -> bool {
        self.data.extra.lazy
    }

    /// Gets the DT_RPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RPATH value
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.data.extra.rpath
    }

    /// Gets the DT_RUNPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RUNPATH value
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.data.extra.runpath
    }

    /// Gets the PT_INTERP value
    ///
    /// # Returns
    /// An optional string slice containing the interpreter path
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.interp
    }

    /// Gets the name of the ELF object
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the program headers of the ELF object
    pub fn phdrs(&self) -> &[ElfPhdr] {
        match &self.phdrs {
            ElfPhdrs::Mmap(phdrs) => &phdrs,
            ElfPhdrs::Vec(phdrs) => &phdrs,
        }
    }

    /// Gets the Global Offset Table pointer
    ///
    /// # Returns
    /// An optional NonNull pointer to the GOT
    #[inline]
    pub(crate) fn got(&self) -> Option<NonNull<usize>> {
        self.data.extra.got_plt
    }

    /// Gets the dynamic relocation information
    ///
    /// # Returns
    /// A reference to the DynamicRelocation structure
    #[inline]
    pub(crate) fn relocation(&self) -> &DynamicRelocation {
        &self.data.extra.relocation
    }

    /// Marks the ELF object as finished and calls the initialization function
    ///
    /// This method marks the ELF object as fully initialized and calls
    /// any registered initialization functions.
    #[inline]
    pub(crate) fn finish(&self) {
        self.data.module.set_init();
        self.data.extra.init.as_ref()();
    }

    /// Gets the GNU_RELRO segment information
    ///
    /// # Returns
    /// An optional reference to the ELFRelro structure
    #[inline]
    pub(crate) fn relro(&self) -> Option<&ELFRelro> {
        self.data.extra.relro.as_ref()
    }

    /// Gets a mutable reference to the user data
    ///
    /// # Returns
    /// An optional mutable reference to the user data
    #[inline]
    pub(crate) fn user_data_mut(&mut self) -> Option<&mut D> {
        self.data.module.user_data_mut()
    }

    /// Gets the symbol table of the ELF object
    #[inline]
    pub(crate) fn symtab(&self) -> &SymbolTable {
        self.data.module.symtab()
    }

    /// Gets the base address of the loaded ELF object
    pub fn base(&self) -> usize {
        self.data.module.base()
    }

    /// Gets the total length of mapped memory for the ELF object
    pub fn mapped_len(&self) -> usize {
        self.data.module.segments().len()
    }

    /// Gets the list of needed library names from the dynamic section
    pub fn needed_libs(&self) -> &[&str] {
        &self.data.extra.needed_libs
    }

    /// Gets the dynamic section pointer
    ///
    /// # Returns
    /// An optional NonNull pointer to the dynamic section
    pub fn dynamic_ptr(&self) -> Option<NonNull<Dyn>> {
        self.data.module.dynamic_ptr()
    }

    /// Gets a reference to the user data
    pub fn user_data(&self) -> &D {
        self.data.module.user_data()
    }

    /// Sets the lazy scope for this component
    ///
    /// # Arguments
    /// * `lazy_scope` - The lazy scope to set
    #[inline]
    pub(crate) fn set_lazy_scope<LazyS>(&self, lazy_scope: LazyS)
    where
        D: 'static,
        LazyS: SymbolLookup + Send + Sync + 'static,
    {
        let info = unsafe {
            &mut *(Arc::as_ptr(&self.data.module.inner.dynamic_info.as_ref().unwrap())
                as *mut DynamicInfo)
        };
        info.lazy_scope = Some(Arc::new(lazy_scope));
    }
}

impl<'hook, H, M, Tls, D> ImageBuilder<'hook, H, M, Tls, D>
where
    H: LoadHook<D>,
    Tls: TlsResolver,
    M: Mmap,
    D: Default,
{
    /// Build the final DynamicImage object
    ///
    /// This method completes the building process by parsing all program
    /// headers and constructing the final DynamicImage object.
    ///
    /// # Arguments
    /// * `phdrs` - Slice of program headers
    ///
    /// # Returns
    /// * `Ok(DynamicImage)` - The built relocated ELF object
    /// * `Err(Error)` - If building fails
    pub(crate) fn build_dynamic(mut self, phdrs: &[ElfPhdr]) -> Result<DynamicImage<D>> {
        // Determine if this is a dynamic library
        let is_dylib = self.ehdr.is_dylib();

        // Parse all program headers
        for phdr in phdrs {
            self.parse_phdr(phdr)?;
        }

        let dynamic_ptr = self.dynamic_ptr.expect("dynamic section not found");

        // Create program headers representation
        let phdrs = self.create_phdrs(phdrs);

        // Build and return the relocated common part
        Ok(DynamicImage {
            entry: self.ehdr.e_entry as usize + if is_dylib { self.segments.base() } else { 0 },
            interp: self
                .interp
                .map(|s| unsafe { CStr::from_ptr(s.as_ptr()).to_str().unwrap() }),
            name: unsafe { core::mem::transmute::<&str, &str>(&self.name) },
            phdrs: phdrs.clone(),
            data: LazyParse {
                state: Cell::new(State::Uninit {
                    phdrs,
                    init_handler: self.init_fn,
                    fini_handler: self.fini_fn,
                    name: self.name,
                    dynamic_ptr,
                    segments: self.segments,
                    relro: self.relro,
                    tls_mod_id: self.tls_mod_id,
                    tls_tp_offset: self.tls_tp_offset,
                    tls_unregister: Tls::unregister,
                    tls_get_addr: Tls::tls_get_addr,
                    user_data: self.user_data,
                }),
            },
        })
    }
}
