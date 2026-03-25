#[cfg(feature = "lazy-binding")]
use crate::elf::ElfRelType;
#[cfg(feature = "lazy-binding")]
use crate::relocation::SymbolLookup;
use crate::sync::{Arc, AtomicBool};
use crate::{
    Result,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, SymbolTable},
    image::{ElfCore, common::CoreInner},
    loader::{ImageBuilder, LifecycleContext, LoadHook},
    logging,
    os::Mmap,
    relocation::{DynamicRelocation, RelocAddr},
    segment::ELFRelro,
    tls::{CoreTlsState, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{ffi::CStr, ptr::NonNull};

#[cfg(feature = "lazy-binding")]
pub(crate) struct LazyBindingInfo {
    pub(crate) pltrel: &'static [ElfRelType],
    pub(crate) scope: Option<Box<dyn SymbolLookup + Send + Sync>>,
}

#[cfg(feature = "lazy-binding")]
impl LazyBindingInfo {
    #[inline]
    pub(crate) fn new(pltrel: Option<&'static [ElfRelType]>) -> Self {
        Self {
            pltrel: pltrel.unwrap_or(&[]),
            scope: None,
        }
    }
}

pub(crate) struct DynamicInfo {
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,
    pub(crate) dynamic_ptr: NonNull<ElfDyn>,
    pub(crate) phdrs: ElfPhdrs,
    #[cfg(feature = "lazy-binding")]
    pub(crate) lazy: LazyBindingInfo,
}

/// Extra data associated with ELF objects during relocation
///
/// This structure holds additional data that is needed during the relocation
/// process but is not part of the core ELF object structure.
struct ElfExtraData {
    /// Indicates whether lazy binding is enabled for this object
    lazy: bool,

    /// Pointer to the Global Offset Table (.got.plt section)
    #[cfg(feature = "lazy-binding")]
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
}

impl core::fmt::Debug for ElfExtraData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfExtraData")
            .field("lazy", &self.lazy)
            .field("relro", &self.relro.is_some())
            .field("needed_libs", &self.needed_libs)
            .finish()
    }
}

/// A common part of relocated ELF objects.
///
/// This structure represents the common components shared by all relocated
/// ELF objects, whether they are dynamic libraries or executables.
/// It contains basic information like entry point, name, and program headers,
/// as well as the parsed data required for relocation and symbol lookup.
pub(crate) struct DynamicImage<D>
where
    D: 'static,
{
    /// Entry point of the ELF object.
    entry: RelocAddr,
    /// PT_INTERP segment value (interpreter path).
    interp: Option<&'static str>,
    /// Program headers.
    phdrs: ElfPhdrs,
    /// Core component containing the basic ELF object information
    module: ElfCore<D>,
    /// Extra data needed for relocation
    extra: ElfExtraData,
}

impl<D> core::fmt::Debug for DynamicImage<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DynamicImage")
            .field("entry", &format_args!("0x{:x}", self.entry.into_inner()))
            .field("module", &self.module)
            .field("extra", &self.extra)
            .finish()
    }
}

impl<D> DynamicImage<D> {
    /// Gets the entry point of the ELF object.
    #[inline]
    pub(crate) fn entry(&self) -> usize {
        self.entry_addr().into_inner()
    }

    #[inline]
    pub(crate) fn entry_addr(&self) -> RelocAddr {
        self.entry
    }

    pub(crate) fn tls_mod_id(&self) -> Option<usize> {
        self.module.tls_mod_id()
    }

    /// Gets the TLS thread pointer offset
    pub(crate) fn tls_tp_offset(&self) -> Option<isize> {
        self.module.tls_tp_offset()
    }

    pub(crate) fn tls_get_addr(&self) -> RelocAddr {
        self.module.tls_get_addr()
    }

    /// Gets the core component reference of the ELF object.
    #[inline]
    pub(crate) fn core_ref(&self) -> &ElfCore<D> {
        &self.module
    }

    /// Gets the core component of the ELF object.
    #[inline]
    pub(crate) fn core(&self) -> ElfCore<D> {
        self.core_ref().clone()
    }

    /// Converts this object into its core component.
    #[inline]
    pub(crate) fn into_core(self) -> ElfCore<D> {
        self.core()
    }

    /// Whether lazy binding is enabled for the current ELF object
    #[inline]
    pub(crate) fn is_lazy(&self) -> bool {
        self.extra.lazy
    }

    /// Gets the DT_RPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RPATH value
    #[inline]
    pub(crate) fn rpath(&self) -> Option<&str> {
        self.extra.rpath
    }

    /// Gets the DT_RUNPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RUNPATH value
    #[inline]
    pub(crate) fn runpath(&self) -> Option<&str> {
        self.extra.runpath
    }

    /// Gets the PT_INTERP value
    ///
    /// # Returns
    /// An optional string slice containing the interpreter path
    #[inline]
    pub(crate) fn interp(&self) -> Option<&str> {
        self.interp
    }

    /// Gets the name of the ELF object
    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.module.name()
    }

    /// Gets the program headers of the ELF object
    pub(crate) fn phdrs(&self) -> &[ElfPhdr] {
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
    #[cfg(feature = "lazy-binding")]
    pub(crate) fn got(&self) -> Option<NonNull<usize>> {
        self.extra.got_plt
    }

    /// Gets the dynamic relocation information
    ///
    /// # Returns
    /// A reference to the DynamicRelocation structure
    #[inline]
    pub(crate) fn relocation(&self) -> &DynamicRelocation {
        &self.extra.relocation
    }

    /// Marks the ELF object as finished and calls the initialization function
    ///
    /// This method marks the ELF object as fully initialized and calls
    /// any registered initialization functions.
    #[inline]
    pub(crate) fn call_init(&self) {
        self.module.set_init();
        self.extra.init.as_ref()();
    }

    /// Gets the GNU_RELRO segment information
    ///
    /// # Returns
    /// An optional reference to the ELFRelro structure
    #[inline]
    pub(crate) fn relro(&self) -> Option<&ELFRelro> {
        self.extra.relro.as_ref()
    }

    /// Gets a mutable reference to the user data
    ///
    /// # Returns
    /// An optional mutable reference to the user data
    #[inline]
    pub(crate) fn user_data_mut(&mut self) -> Option<&mut D> {
        self.module.user_data_mut()
    }

    /// Gets the base address of the loaded ELF object
    pub(crate) fn base(&self) -> usize {
        self.module.base()
    }

    /// Gets the total length of mapped memory for the ELF object
    pub(crate) fn mapped_len(&self) -> usize {
        self.module.segments().len()
    }

    /// Gets the list of needed library names from the dynamic section
    pub(crate) fn needed_libs(&self) -> &[&str] {
        &self.extra.needed_libs
    }

    /// Gets the dynamic section pointer
    ///
    /// # Returns
    /// An optional NonNull pointer to the dynamic section
    pub(crate) fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn>> {
        self.module.dynamic_ptr()
    }

    /// Gets a reference to the user data
    pub(crate) fn user_data(&self) -> &D {
        self.module.user_data()
    }
}

impl<D: 'static> DynamicImage<D> {
    /// Build a dynamic image from the intermediate loader state.
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        mut builder: ImageBuilder<'hook, H, M, Tls, D>,
        phdrs: &[ElfPhdr],
    ) -> Result<Self>
    where
        H: LoadHook,
        Tls: TlsResolver,
        M: Mmap,
    {
        // Determine if this is a dynamic library
        let is_dylib = builder.ehdr.is_dylib();

        // Parse all program headers
        builder.parse_phdrs(phdrs)?;

        let dynamic_ptr = builder.dynamic_ptr.expect("dynamic section not found");

        // Create program headers representation
        let phdrs_repr = builder.create_phdrs(phdrs);

        let dynamic = ElfDynamic::new(dynamic_ptr.as_ptr(), &builder.segments).unwrap();

        logging::trace!("[{}] Dynamic info: {:?}", builder.name, dynamic);

        let relocation = DynamicRelocation::new(
            dynamic.pltrel,
            dynamic.dynrel,
            dynamic.relr,
            dynamic.rel_count,
        );

        let static_tls = builder.static_tls | dynamic.static_tls;

        // Create symbol table from dynamic section
        let symtab = SymbolTable::from_dynamic(&dynamic);

        // Collect needed library names
        let needed_libs: Vec<&'static str> = dynamic
            .needed_libs
            .iter()
            .map(|needed_lib| symtab.strtab().get_str(needed_lib.get()))
            .collect();

        if !needed_libs.is_empty() {
            logging::debug!("[{}] Dependencies: {:?}", builder.name, needed_libs);
        }

        let init_handler = builder.init_fn;

        let (tls_mod_id, tls_tp_offset) = if let Some(info) = &builder.tls_info {
            // The Tls::register will register the TLS module and return the ID.
            if static_tls {
                let (mod_id, offset) = Tls::register_static(info)?;
                (Some(mod_id), Some(offset))
            } else {
                (Some(Tls::register(info)?), None)
            }
        } else {
            (None, None)
        };

        // Build and return the relocated common part
        Ok(DynamicImage {
            entry: if is_dylib {
                builder
                    .segments
                    .base_addr()
                    .offset(builder.ehdr.e_entry as usize)
            } else {
                RelocAddr::new(builder.ehdr.e_entry as usize)
            },
            interp: builder
                .interp
                .map(|s| unsafe { CStr::from_ptr(s.as_ptr()).to_str().unwrap() }),
            phdrs: phdrs_repr.clone(),
            extra: ElfExtraData {
                // Determine if lazy binding should be enabled
                lazy: cfg!(feature = "lazy-binding") && !dynamic.bind_now,

                // Store GNU_RELRO segment information
                relro: builder.relro,

                // Store relocation information
                relocation,

                // Create initialization function
                init: Box::new(move || {
                    init_handler.call(&LifecycleContext::new(
                        dynamic.init_fn,
                        dynamic.init_array_fn,
                    ))
                }),

                // Store GOT pointer
                #[cfg(feature = "lazy-binding")]
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
            },
            module: ElfCore {
                inner: Arc::new(CoreInner {
                    is_init: AtomicBool::new(false),
                    name: builder.name,
                    symtab,
                    fini: dynamic.fini_fn,
                    fini_array: dynamic.fini_array_fn,
                    fini_handler: builder.fini_fn,
                    user_data: builder.user_data,
                    dynamic_info: Some(Arc::new(DynamicInfo {
                        eh_frame_hdr: builder.eh_frame_hdr,
                        dynamic_ptr: NonNull::new(dynamic.dyn_ptr as _).unwrap(),
                        phdrs: phdrs_repr,
                        #[cfg(feature = "lazy-binding")]
                        lazy: LazyBindingInfo::new(dynamic.pltrel),
                    })),
                    tls: CoreTlsState::new(
                        tls_mod_id,
                        tls_tp_offset,
                        RelocAddr::from_ptr(Tls::tls_get_addr as *const ()),
                        Tls::unregister,
                    ),
                    segments: builder.segments,
                }),
            },
        })
    }
}
