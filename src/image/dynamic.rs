use crate::arch::NativeArch;
#[cfg(feature = "lazy-binding")]
use crate::elf::ElfRelType;
use crate::sync::{Arc, AtomicBool};
use crate::{
    ParsePhdrError, Result,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, Lifecycle, SymbolTable},
    loader::{DynLifecycleHandler, ImageBuilder, LoadHook},
    logging,
    os::Mmap,
    relocation::{
        DynamicRelocation, EmuContext, Emulator, RelocAddr, Relocatable, RelocateArgs,
        RelocationArch, RelocationHandler, Relocator,
    },
    segment::ELFRelro,
    tls::{CoreTlsState, TlsInfo, TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{boxed::Box, vec::Vec};
use core::{ffi::CStr, marker::PhantomData, ptr::NonNull};

use super::{ElfCore, LoadedCore, core::CoreFiniHandler, core::CoreInner};

#[cfg(feature = "lazy-binding")]
pub(crate) struct LazyBindingInfo<Arch: RelocationArch = NativeArch> {
    pub(crate) pltrel: &'static [ElfRelType<Arch>],
    pub(crate) scope: Option<crate::image::ModuleScope<Arch>>,
}

#[cfg(feature = "lazy-binding")]
impl<Arch: RelocationArch> LazyBindingInfo<Arch> {
    #[inline]
    pub(crate) fn new(pltrel: Option<&'static [ElfRelType<Arch>]>) -> Self {
        Self {
            pltrel: pltrel.unwrap_or(&[]),
            scope: None,
        }
    }
}

pub(crate) struct DynamicInfo<Arch: RelocationArch = NativeArch> {
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,
    pub(crate) dynamic_ptr: NonNull<ElfDyn<Arch::Layout>>,
    pub(crate) phdrs: ElfPhdrs<Arch::Layout>,
    pub(crate) soname: Option<&'static str>,
    #[cfg(feature = "lazy-binding")]
    pub(crate) lazy: LazyBindingInfo<Arch>,
}

pub(crate) struct RawDynamicParts<D, Arch: RelocationArch = NativeArch> {
    pub(crate) name: alloc::string::String,
    pub(crate) entry: RelocAddr,
    pub(crate) interp: Option<&'static str>,
    pub(crate) phdrs: ElfPhdrs<Arch::Layout>,
    pub(crate) dynamic_ptr: NonNull<ElfDyn<Arch::Layout>>,
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,
    pub(crate) tls_info: Option<TlsInfo>,
    pub(crate) force_static_tls: bool,
    pub(crate) relro: Option<ELFRelro>,
    pub(crate) segments: crate::segment::ElfSegments,
    pub(crate) init_fn: DynLifecycleHandler,
    pub(crate) fini_fn: DynLifecycleHandler,
    pub(crate) user_data: D,
}

/// Extra data associated with ELF objects during relocation
///
/// This structure holds additional data that is needed during the relocation
/// process but is not part of the core ELF object structure.
struct ElfExtraData<Arch: RelocationArch = NativeArch> {
    /// Indicates whether lazy binding is enabled for this object
    lazy: bool,

    /// Pointer to the Global Offset Table (.got.plt section)
    #[cfg(feature = "lazy-binding")]
    got_plt: Option<NonNull<usize>>,

    /// Dynamic relocation information (rela.dyn and rela.plt)
    relocation: DynamicRelocation<Arch>,

    /// GNU_RELRO segment information for memory protection
    relro: Option<ELFRelro>,

    /// Custom initialization handler.
    init_handler: DynLifecycleHandler,

    /// Initialization functions to be called after relocation.
    init: Lifecycle<'static>,

    /// DT_RPATH value from the dynamic section
    rpath: Option<&'static str>,

    /// DT_RUNPATH value from the dynamic section
    runpath: Option<&'static str>,

    /// List of needed library names from the dynamic section
    needed_libs: Box<[&'static str]>,
}

impl<Arch: RelocationArch> core::fmt::Debug for ElfExtraData<Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfExtraData")
            .field("lazy", &self.lazy)
            .field("relro", &self.relro.is_some())
            .field("needed_libs", &self.needed_libs)
            .finish()
    }
}

/// A mapped but unrelocated dynamic ELF image.
///
/// This is the common raw representation for ELF images with a `PT_DYNAMIC`
/// segment, including shared objects and dynamically linked executables.
///
/// The optional `Arch` type parameter selects which relocation type numbering
/// is applied during [`Relocator::relocate`]. By default it is
/// [`crate::arch::NativeArch`] (the host architecture), which preserves the prior
/// single-architecture behavior. Cross-architecture loading instead carries
/// one of the per-ISA backends (e.g.
/// [`crate::arch::x86_64::relocation::X86_64Arch`]).
pub struct RawDynamic<D, Arch = NativeArch>
where
    D: 'static,
    Arch: RelocationArch,
{
    /// Entry point of the ELF object.
    entry: RelocAddr,
    /// PT_INTERP segment value (interpreter path).
    interp: Option<&'static str>,
    /// Core component containing the basic ELF object information
    module: ElfCore<D, Arch>,
    /// Extra data needed for relocation
    extra: ElfExtraData<Arch>,
    /// Tag identifying which relocation backend is used during relocation.
    ///
    /// `Arch` is a zero-sized type, so this field has no runtime cost.
    _arch: PhantomData<fn() -> Arch>,
}

impl<D, Arch: RelocationArch> core::fmt::Debug for RawDynamic<D, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawDynamic")
            .field("entry", &format_args!("0x{:x}", self.entry.into_inner()))
            .field("module", &self.module)
            .field("extra", &self.extra)
            .finish()
    }
}

impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
    /// Gets the entry point of the ELF object.
    #[inline]
    pub fn entry(&self) -> usize {
        self.entry_addr().into_inner()
    }

    #[inline]
    pub(crate) fn entry_addr(&self) -> RelocAddr {
        self.entry
    }

    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        self.module.tls_mod_id()
    }

    /// Gets the TLS thread pointer offset
    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        self.module.tls_tp_offset()
    }

    pub(crate) fn tls_get_addr(&self) -> RelocAddr {
        self.module.tls_get_addr()
    }

    /// Gets the core component reference of the ELF object.
    #[inline]
    pub fn core_ref(&self) -> &ElfCore<D, Arch> {
        &self.module
    }

    /// Gets the core component of the ELF object.
    #[inline]
    pub fn core(&self) -> ElfCore<D, Arch> {
        self.core_ref().clone()
    }

    /// Converts this object into its core component.
    #[inline]
    pub fn into_core(self) -> ElfCore<D, Arch> {
        self.core()
    }

    /// Whether lazy binding is enabled for the current ELF object
    #[inline]
    pub fn is_lazy(&self) -> bool {
        self.extra.lazy
    }

    /// Gets the DT_RPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RPATH value
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.extra.rpath
    }

    /// Gets the DT_RUNPATH value
    ///
    /// # Returns
    /// An optional string slice containing the RUNPATH value
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.extra.runpath
    }

    /// Gets the DT_SONAME value
    ///
    /// # Returns
    /// An optional string slice containing the shared-object name
    #[inline]
    pub fn soname(&self) -> Option<&str> {
        self.module.soname()
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
        self.module.name()
    }

    /// Gets the program headers of the ELF object
    pub fn phdrs(&self) -> &[ElfPhdr<Arch::Layout>] {
        self.module
            .phdrs()
            .expect("raw dynamic image should always carry program headers")
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
    pub(crate) fn relocation(&self) -> &DynamicRelocation<Arch> {
        &self.extra.relocation
    }

    /// Marks the ELF object as finished and calls the initialization function
    ///
    /// This method marks the ELF object as fully initialized and calls
    /// any registered initialization functions.
    #[inline]
    pub(crate) fn call_init(&self) {
        self.module.set_init();
        self.extra.init_handler.call(&self.extra.init);
    }

    /// Marks the ELF object as initialized and delegates initialization to an emulator.
    pub(crate) fn call_init_with_emu(&self, emu: Arc<dyn Emulator<Arch>>) -> Result<()> {
        let ctx = EmuContext::new(self.core_ref());
        emu.call_init(&ctx, &self.extra.init)?;
        unsafe {
            self.core_ref().set_emu_fini(emu);
        }
        self.module.set_init();
        Ok(())
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
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        self.module.user_data_mut()
    }

    /// Gets the base address of the loaded ELF object
    pub fn base(&self) -> usize {
        self.module.base()
    }

    /// Gets the length of the bounding runtime span covered by mapped memory.
    pub fn mapped_len(&self) -> usize {
        self.module.mapped_len()
    }

    /// Gets the lowest runtime address covered by mapped memory.
    pub(crate) fn mapped_base(&self) -> usize {
        self.module.mapped_base()
    }

    /// Returns whether `addr` is inside one of this image's mapped slices.
    pub fn contains_addr(&self, addr: usize) -> bool {
        self.module.contains_addr(addr)
    }

    /// Gets the list of needed library names from the dynamic section
    pub fn needed_libs(&self) -> &[&str] {
        &self.extra.needed_libs
    }

    /// Gets the dynamic section pointer
    ///
    /// # Returns
    /// An optional NonNull pointer to the dynamic section
    pub fn dynamic_ptr(&self) -> Option<NonNull<ElfDyn<Arch::Layout>>> {
        self.module.dynamic_ptr()
    }

    /// Gets a reference to the user data
    pub fn user_data(&self) -> &D {
        self.module.user_data()
    }
}

impl<D: 'static, Arch: RelocationArch> RawDynamic<D, Arch> {
    pub(crate) fn from_parts<Tls>(parts: RawDynamicParts<D, Arch>) -> Result<Self>
    where
        Tls: TlsResolver,
    {
        let RawDynamicParts {
            name,
            entry,
            interp,
            phdrs,
            dynamic_ptr,
            eh_frame_hdr,
            tls_info,
            force_static_tls,
            relro,
            segments,
            init_fn,
            fini_fn,
            user_data,
        } = parts;

        let dynamic = ElfDynamic::<Arch>::new(dynamic_ptr.as_ptr(), &segments)?;

        logging::trace!("[{}] Dynamic info: {:?}", name, dynamic);

        let relocation = DynamicRelocation::new(
            dynamic.pltrel,
            dynamic.dynrel,
            dynamic.relr,
            dynamic.rel_count,
        )?;

        let static_tls = force_static_tls | dynamic.static_tls;
        let symtab = SymbolTable::from_dynamic(&dynamic);
        let needed_libs: Vec<&'static str> = dynamic
            .needed_libs
            .iter()
            .map(|needed_lib| symtab.strtab().get_str(needed_lib.get()))
            .collect();

        if !needed_libs.is_empty() {
            logging::debug!("[{}] Dependencies: {:?}", name, needed_libs);
        }
        let soname = dynamic
            .soname_off
            .map(|soname_off| symtab.strtab().get_str(soname_off.get()));

        let (tls_mod_id, tls_tp_offset) = if let Some(info) = &tls_info {
            if static_tls {
                let (mod_id, offset) = Tls::register_static(info)?;
                (Some(mod_id), Some(offset))
            } else {
                (Some(Tls::register(info)?), None)
            }
        } else {
            (None, None)
        };

        Ok(RawDynamic {
            entry,
            interp,
            extra: ElfExtraData {
                lazy: cfg!(feature = "lazy-binding") && !dynamic.bind_now,
                relro,
                relocation,
                init_handler: init_fn,
                init: Lifecycle::new(dynamic.init_fn, dynamic.init_array_fn),
                #[cfg(feature = "lazy-binding")]
                got_plt: dynamic.got_plt,
                rpath: dynamic
                    .rpath_off
                    .map(|rpath_off| symtab.strtab().get_str(rpath_off.get())),
                needed_libs: needed_libs.into_boxed_slice(),
                runpath: dynamic
                    .runpath_off
                    .map(|runpath_off| symtab.strtab().get_str(runpath_off.get())),
            },
            module: ElfCore {
                inner: Arc::new(CoreInner {
                    is_init: AtomicBool::new(false),
                    name,
                    symtab,
                    fini: Lifecycle::new(dynamic.fini_fn, dynamic.fini_array_fn),
                    fini_handler: CoreFiniHandler::Native(fini_fn),
                    user_data,
                    dynamic_info: Some(Arc::new(DynamicInfo {
                        eh_frame_hdr,
                        dynamic_ptr,
                        phdrs,
                        soname,
                        #[cfg(feature = "lazy-binding")]
                        lazy: LazyBindingInfo::new(dynamic.pltrel),
                    })),
                    tls: CoreTlsState::new(
                        tls_mod_id,
                        tls_tp_offset,
                        RelocAddr::from_ptr(Tls::tls_get_addr as *const ()),
                        Tls::unregister,
                    ),
                    segments,
                }),
            },
            _arch: PhantomData,
        })
    }

    /// Build a dynamic image from the intermediate loader state.
    pub(crate) fn from_builder<'hook, H, M, Tls>(
        mut builder: ImageBuilder<'hook, H, M, Tls, D, Arch::Layout>,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<Self>
    where
        H: LoadHook<Arch::Layout>,
        Tls: TlsResolver,
        M: Mmap,
    {
        // Parse all program headers
        builder.parse_phdrs(phdrs)?;

        let dynamic_ptr = builder
            .dynamic_ptr
            .ok_or(ParsePhdrError::MissingDynamicSection)?;
        let phdrs = builder.create_phdrs(phdrs);
        Self::from_parts::<Tls>(RawDynamicParts {
            name: builder.name,
            entry: if builder.ehdr.is_dylib() {
                builder.segments.base_addr().offset(builder.ehdr.e_entry())
            } else {
                RelocAddr::new(builder.ehdr.e_entry())
            },
            interp: builder
                .interp
                .map(|s| unsafe { CStr::from_ptr(s.as_ptr()) }.to_str())
                .transpose()
                .map_err(|_| ParsePhdrError::InvalidUtf8 { field: "PT_INTERP" })?,
            phdrs,
            dynamic_ptr,
            eh_frame_hdr: builder.eh_frame_hdr,
            tls_info: builder.tls_info,
            force_static_tls: builder.static_tls,
            relro: builder.relro,
            segments: builder.segments,
            init_fn: builder.init_fn,
            fini_fn: builder.fini_fn,
            user_data: builder.user_data,
        })
    }

    /// Creates a relocation builder for this dynamic image.
    pub fn relocator(self) -> Relocator<Self, (), (), D, Arch> {
        Relocator::new().with_object(self)
    }
}

impl<D: 'static, Arch: RelocationArch> Relocatable<D> for RawDynamic<D, Arch> {
    type Output = LoadedCore<D, Arch>;
    type Arch = Arch;

    fn relocate<PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, Arch, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        self.relocate_impl::<_, _>(args)
    }
}
