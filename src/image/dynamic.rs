use crate::arch::NativeArch;
#[cfg(feature = "lazy-binding")]
use crate::elf::ElfRelType;
use crate::sync::{Arc, AtomicBool};
use crate::{
    ParsePhdrError, Result,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, Lifecycle, LifecycleSpec, SymbolTable},
    input::{Path, PathBuf},
    loader::ImageBuilder,
    logging,
    observer::{
        DtDebugEntry, LifecycleEvent, LifecyclePhase, LoadObserver, RelocationObserver,
        default_lifecycle_executor, noop_lifecycle_executor,
    },
    os::{HostRegion, MappedView, RegionAccess, VmAddr, VmOffset},
    relocation::{
        DynamicRelocation, Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator,
    },
    segment::ELFRelro,
    tls::{CoreTlsState, TlsInfo, TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{boxed::Box, vec::Vec};
use core::{cell::OnceCell, marker::PhantomData, ptr::NonNull};

use super::{ElfCore, LoadedCore, core::CoreInner};

#[cfg(feature = "lazy-binding")]
pub(crate) struct LazyBindingInfo<Arch: RelocationArch = NativeArch> {
    pub(crate) pltrel: MappedView<ElfRelType<Arch>>,
    pub(crate) scope: OnceCell<crate::image::ModuleScope<Arch>>,
}

#[cfg(feature = "lazy-binding")]
impl<Arch: RelocationArch> LazyBindingInfo<Arch> {
    #[inline]
    pub(crate) fn new(pltrel: Option<MappedView<ElfRelType<Arch>>>) -> Self {
        Self {
            pltrel: pltrel.unwrap_or_else(MappedView::empty),
            scope: OnceCell::new(),
        }
    }
}

pub(crate) struct DynamicInfo<Arch: RelocationArch = NativeArch> {
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,
    pub(crate) phdrs: ElfPhdrs<Arch::Layout>,
    pub(crate) soname: Option<&'static str>,
    #[cfg(feature = "lazy-binding")]
    pub(crate) lazy: LazyBindingInfo<Arch>,
}

pub(crate) struct RawDynamicParts<
    D,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) entry: VmAddr,
    pub(crate) interp: Option<&'static str>,
    pub(crate) phdrs: ElfPhdrs<Arch::Layout>,
    pub(crate) dynamic: MappedView<ElfDyn<Arch::Layout>>,
    pub(crate) dynamic_addr: VmAddr,
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,
    pub(crate) tls_info: Option<TlsInfo>,
    pub(crate) force_static_tls: bool,
    pub(crate) relro: Option<ELFRelro>,
    pub(crate) segments: crate::segment::ElfSegments<R>,
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

    /// Runtime address of the dynamic section.
    dynamic_addr: VmAddr,

    /// Initialization functions to resolve after relocation.
    init: LifecycleSpec,

    /// Finalization functions to resolve after relocation.
    fini: LifecycleSpec,

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
/// The optional `Arch` type parameter selects the target architecture used
/// during [`Relocator::relocate`]. By default it is [`crate::arch::NativeArch`].
pub struct RawDynamic<D, Arch = NativeArch, R: RegionAccess = HostRegion>
where
    D: 'static,
    Arch: RelocationArch,
{
    /// Entry point of the ELF object.
    entry: VmAddr,
    /// PT_INTERP segment value (interpreter path).
    interp: Option<&'static str>,
    /// Core component containing the basic ELF object information
    module: ElfCore<D, Arch, R>,
    /// Extra data needed for relocation
    extra: ElfExtraData<Arch>,
    /// Target architecture marker used during relocation.
    _arch: PhantomData<fn() -> Arch>,
}

impl<D, Arch: RelocationArch, R: RegionAccess> core::fmt::Debug for RawDynamic<D, Arch, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawDynamic")
            .field("entry", &format_args!("0x{:x}", self.entry.get()))
            .field("module", &self.module)
            .field("extra", &self.extra)
            .finish()
    }
}

impl<D, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
    /// Gets the entry point of the ELF object.
    #[inline]
    pub fn entry(&self) -> usize {
        self.entry_addr().get()
    }

    #[inline]
    pub(crate) fn entry_addr(&self) -> VmAddr {
        self.entry
    }

    /// Returns the TLS module id assigned to this image, when registered.
    pub fn tls_mod_id(&self) -> Option<TlsModuleId> {
        self.module.tls_mod_id()
    }

    /// Gets the TLS thread pointer offset
    pub fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        self.module.tls_tp_offset()
    }

    pub(crate) fn tls_get_addr(&self) -> VmAddr {
        self.module.tls_get_addr()
    }

    /// Gets the core component reference of the ELF object.
    #[inline]
    pub fn core_ref(&self) -> &ElfCore<D, Arch, R> {
        &self.module
    }

    /// Gets the core component of the ELF object.
    #[inline]
    pub fn core(&self) -> ElfCore<D, Arch, R> {
        self.core_ref().clone()
    }

    /// Converts this object into its core component.
    #[inline]
    pub fn into_core(self) -> ElfCore<D, Arch, R> {
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

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.module.path()
    }

    /// Gets the ELF module identity used for diagnostics.
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

    pub(crate) fn resolve_lifecycle(&self) -> Result<(Lifecycle, Lifecycle)> {
        let segments = self.module.segments();
        let init = self
            .extra
            .init
            .resolve::<Arch::Layout, R>(segments, "DT_INIT_ARRAY size is malformed")?;
        let fini = self
            .extra
            .fini
            .resolve::<Arch::Layout, R>(segments, "DT_FINI_ARRAY size is malformed")?;
        Ok((init, fini))
    }

    /// Marks the ELF object as finished and calls the initialization function
    ///
    /// This method marks the ELF object as fully initialized and calls
    /// any registered initialization functions.
    #[inline]
    pub(crate) fn call_init<Obs>(&self, observer: &mut Obs, init: &Lifecycle) -> Result<()>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        self.module.set_init();
        let mut event = if Arch::SUPPORTS_NATIVE_RUNTIME {
            LifecycleEvent::with_executor(
                LifecyclePhase::Init,
                self.name(),
                init,
                self.module.segments(),
                default_lifecycle_executor(),
            )
        } else {
            LifecycleEvent::with_executor(
                LifecyclePhase::Init,
                self.name(),
                init,
                self.module.segments(),
                noop_lifecycle_executor(),
            )
        };
        observer.on_lifecycle(&mut event)?;
        event.run();
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
    pub fn base(&self) -> VmAddr {
        self.module.base()
    }

    /// Gets the length of the bounding runtime span covered by mapped memory.
    pub fn mapped_len(&self) -> usize {
        self.module.mapped_len()
    }

    /// Gets the lowest runtime address covered by mapped memory.
    pub(crate) fn mapped_base(&self) -> VmAddr {
        self.module.mapped_base()
    }

    /// Returns whether `addr` is inside one of this image's mapped slices.
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        self.module.contains_addr(addr)
    }

    /// Gets the list of needed library names from the dynamic section
    pub fn needed_libs(&self) -> &[&str] {
        &self.extra.needed_libs
    }

    #[inline]
    pub(crate) fn dynamic_addr(&self) -> VmAddr {
        self.extra.dynamic_addr
    }

    #[inline]
    /// Gets a reference to the user data
    pub fn user_data(&self) -> &D {
        self.module.user_data()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
    pub(crate) fn from_parts<Tls, Obs>(
        parts: RawDynamicParts<D, Arch, R>,
        observer: &mut Obs,
    ) -> Result<Self>
    where
        Tls: TlsResolver,
        Obs: LoadObserver<Arch> + ?Sized,
    {
        let RawDynamicParts {
            path,
            entry,
            interp,
            phdrs,
            dynamic,
            dynamic_addr,
            eh_frame_hdr,
            tls_info,
            force_static_tls,
            relro,
            segments,
            user_data,
        } = parts;

        let dynamic = ElfDynamic::<Arch>::new(dynamic, dynamic_addr, &segments)?;
        if let Some(addr) = dynamic.dt_debug_addr {
            observer.on_dt_debug(DtDebugEntry::new(addr, &segments))?;
        }

        logging::trace!("[{}] Dynamic info: {:?}", path, dynamic);

        let relocation = DynamicRelocation::new(
            dynamic.pltrel.clone(),
            dynamic.dynrel.clone(),
            dynamic.relr.clone(),
            dynamic.rel_count,
            dynamic.pltrel_is_dynrel_tail,
        )?;

        let static_tls = force_static_tls | dynamic.static_tls;
        let symtab = SymbolTable::from_dynamic(&dynamic, &segments)?;
        let needed_libs: Vec<&'static str> = dynamic
            .needed_libs
            .iter()
            .map(|needed_lib| symtab.strtab().get_str(needed_lib.get()))
            .collect();

        if !needed_libs.is_empty() {
            logging::debug!("[{}] Dependencies: {:?}", path, needed_libs);
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
            extra: ElfExtraData::<Arch> {
                lazy: cfg!(feature = "lazy-binding") && !dynamic.bind_now,
                relro,
                dynamic_addr,
                relocation,
                init: dynamic.init,
                fini: dynamic.fini,
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
                    path,
                    symtab,
                    fini: OnceCell::new(),
                    fini_executor: OnceCell::new(),
                    unload_hook: OnceCell::new(),
                    user_data,
                    dynamic_info: Some(Arc::new(DynamicInfo {
                        eh_frame_hdr,
                        phdrs,
                        soname,
                        #[cfg(feature = "lazy-binding")]
                        lazy: LazyBindingInfo::new(dynamic.pltrel.clone()),
                    })),
                    tls: CoreTlsState::new(
                        tls_mod_id,
                        tls_tp_offset,
                        VmAddr::from_ptr(Tls::tls_get_addr as *const ()),
                        Tls::unregister,
                    ),
                    segments,
                }),
            },
            _arch: PhantomData,
        })
    }

    /// Creates a relocation builder for this dynamic image.
    pub fn relocator(self) -> Relocator<Self, (), (), D, Arch> {
        Relocator::new().with_object(self)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
    /// Build a dynamic image from the intermediate loader state.
    pub(crate) fn from_builder<'obs, Obs, Tls>(
        mut builder: ImageBuilder<'obs, Obs, Tls, D, Arch, R>,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<Self>
    where
        Obs: LoadObserver<Arch>,
        Tls: TlsResolver,
    {
        // Parse all program headers
        builder.parse_phdrs(phdrs)?;

        let phdrs = builder.create_phdrs(phdrs)?;
        let dynamic = builder
            .dynamic
            .ok_or(ParsePhdrError::MissingDynamicSection)?;
        let parts = RawDynamicParts {
            path: builder.path,
            entry: if builder.ehdr.is_dylib() {
                builder.segments.base() + VmOffset::new(builder.ehdr.e_entry())
            } else {
                VmAddr::new(builder.ehdr.e_entry())
            },
            interp: builder.interp,
            phdrs,
            dynamic,
            dynamic_addr: builder
                .dynamic_addr
                .ok_or(ParsePhdrError::MissingDynamicSection)?,
            eh_frame_hdr: builder.eh_frame_hdr,
            tls_info: builder.tls_info,
            force_static_tls: builder.static_tls,
            relro: builder.relro,
            segments: builder.segments,
            user_data: builder.user_data,
        };
        Self::from_parts::<Tls, _>(parts, builder.observer)
    }
}

impl<D, Arch, R> Relocatable<D> for RawDynamic<D, Arch, R>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    <Arch::Layout as crate::elf::ElfLayout>::Word: crate::ByteRepr,
{
    type Output = LoadedCore<D, Arch, R>;
    type Arch = Arch;

    fn relocate<PreH, PostH, Obs>(
        self,
        args: RelocateArgs<'_, D, Arch, PreH, PostH, Obs>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        self.relocate_impl::<_, _, _>(args)
    }
}
