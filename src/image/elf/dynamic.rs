use crate::arch::NativeArch;
#[cfg(feature = "lazy-binding")]
use crate::elf::ElfRelType;
use crate::sync::{Arc, AtomicBool};
use crate::{
    ParseDynamicError, ParsePhdrError, Result,
    elf::{
        ElfDyn, ElfDynamic, ElfDynamicTag, ElfLayout, ElfPhdr, ElfPhdrs, ElfStringTable, ElfSymbol,
        HashTable, Lifecycle, LifecycleSpec, SymbolTable,
    },
    input::{Path, PathBuf},
    loader::ImageBuilder,
    logging,
    memory::{HostRegion, ImageMemory, MappedView, RegionAccess, VmAddr, VmOffset},
    observer::{InitEvent, RelocationObserver},
    relocation::{
        DynamicRelocation, Relocatable, RelocateArgs, RelocationArch, RelocationHandler, Relocator,
    },
    runtime::CodeExecutor,
    segment::{ElfSegments, MemoryProtection},
    tls::{CoreTlsDescArgs, CoreTlsState, TlsInfo, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{cell::OnceCell, mem::size_of, ptr::NonNull};

use crate::image::{ElfCore, LoadedCore, ModuleTls, core::CoreInner, exports_handle};

impl<L: ElfLayout> SymbolTable<L> {
    pub(crate) fn from_dynamic<Arch, R>(
        dynamic: &ElfDynamic<Arch>,
        segments: &ElfSegments<R>,
    ) -> Result<Self>
    where
        Arch: RelocationArch<Layout = L>,
        R: RegionAccess,
    {
        let hashtab = HashTable::from_dynamic(dynamic, segments)?;
        let symbol_count = hashtab.count_syms();

        let symtab_off = dynamic
            .symtab
            .checked_offset_from(segments.base())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let symtab_size = symbol_count
            .checked_mul(size_of::<ElfSymbol<L>>())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let symbols = segments
            .read_view::<ElfSymbol<L>>(symtab_off, symtab_size)
            .ok_or(ParseDynamicError::MalformedSymbolTable {
                detail: "DT_SYMTAB symbol table size is malformed",
            })?
            .as_slice();

        let strtab_size = dynamic
            .strtab_size
            .ok_or(ParseDynamicError::MissingRequiredTag { tag: "DT_STRSZ" })?;
        let strtab_off = dynamic
            .strtab
            .checked_offset_from(segments.base())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let strtab = segments
            .read_view::<u8>(strtab_off, strtab_size.get())
            .ok_or(ParseDynamicError::MalformedStringTable {
                detail: "DT_STRTAB string table size is malformed",
            })?;
        let strtab = ElfStringTable::new(strtab);

        #[cfg(feature = "version")]
        let version = crate::elf::version::ELFVersion::new(
            dynamic.version_idx,
            dynamic.verneed,
            dynamic.verdef,
            &strtab,
        );

        Ok(Self {
            hashtab,
            symbols,
            strtab,
            #[cfg(feature = "version")]
            version,
        })
    }
}

#[cfg(feature = "lazy-binding")]
pub(crate) struct LazyBindingInfo<Arch: RelocationArch = NativeArch> {
    pub(crate) pltrel: MappedView<ElfRelType<Arch>>,
    pub(crate) symtab: SymbolTable<Arch::Layout>,
    pub(crate) scope: OnceCell<crate::image::ModuleScope<Arch>>,
}

#[cfg(feature = "lazy-binding")]
impl<Arch: RelocationArch> LazyBindingInfo<Arch> {
    #[inline]
    pub(crate) fn new(
        pltrel: Option<MappedView<ElfRelType<Arch>>>,
        symtab: SymbolTable<Arch::Layout>,
    ) -> Self {
        Self {
            pltrel: pltrel.unwrap_or_else(MappedView::empty),
            symtab,
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
    pub(crate) relro: Option<MemoryProtection>,
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

    /// GNU_RELRO memory protection.
    relro: Option<MemoryProtection>,

    /// Runtime address of the dynamic section.
    dynamic_addr: VmAddr,

    /// Runtime address of the DT_DEBUG entry, when present.
    dt_debug_addr: Option<VmAddr>,

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

    /// Relocation-only dynamic symbol table.
    symtab: SymbolTable<Arch::Layout>,
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

    /// Returns TLS metadata associated with this image.
    pub fn tls(&self) -> ModuleTls {
        self.module.tls()
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
    pub(crate) fn call_init<Obs>(
        &self,
        observer: &mut Obs,
        init: &Lifecycle,
        executor: &dyn CodeExecutor<Arch>,
    ) -> Result<()>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        self.module.set_init();
        let segments = self.module.segments();
        let mut event = InitEvent::new(self.core_ref(), init);
        observer.on_init(&mut event)?;
        event.run_with(segments, executor)?;
        Ok(())
    }

    /// Gets the GNU_RELRO memory protection.
    ///
    /// # Returns
    /// An optional reference to the protection range.
    #[inline]
    pub(crate) fn relro(&self) -> Option<&MemoryProtection> {
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

    /// Returns the mapped segments owned by this image.
    pub fn segments(&self) -> &ElfSegments<R> {
        self.module.segments()
    }

    /// Gets the list of needed library names from the dynamic section
    pub fn needed_libs(&self) -> &[&str] {
        &self.extra.needed_libs
    }

    #[inline]
    pub(crate) fn dynamic_addr(&self) -> VmAddr {
        self.extra.dynamic_addr
    }

    /// Returns the runtime address of the `DT_DEBUG` dynamic entry, when present.
    #[inline]
    pub fn dt_debug_addr(&self) -> Option<VmAddr> {
        self.extra.dt_debug_addr
    }

    /// Writes the runtime address of an externally owned `r_debug` object into `DT_DEBUG`.
    ///
    /// Returns `Ok(true)` when this image has a `DT_DEBUG` entry and it was patched,
    /// or `Ok(false)` when no `DT_DEBUG` entry exists.
    #[inline]
    pub fn write_dt_debug_addr(&self, addr: VmAddr) -> Result<bool> {
        let Some(dt_debug_addr) = self.dt_debug_addr() else {
            return Ok(false);
        };
        let entry = ElfDyn::<Arch::Layout>::new(ElfDynamicTag::DEBUG, addr.get());
        unsafe { ImageMemory::write_value(self.module.segments(), dt_debug_addr, entry)? };
        Ok(true)
    }

    #[inline]
    pub(crate) fn symtab(&self) -> &SymbolTable<Arch::Layout> {
        &self.extra.symtab
    }

    #[inline]
    /// Gets a reference to the user data
    pub fn user_data(&self) -> &D {
        self.module.user_data()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
    pub(crate) fn from_parts<Tls>(parts: RawDynamicParts<D, Arch, R>) -> Result<Self>
    where
        Tls: TlsResolver,
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
        let exports = symtab.clone();
        #[cfg(feature = "lazy-binding")]
        let lazy_symtab = symtab.clone();
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

        let tls_image = if let Some(info) = &tls_info {
            Some(
                segments
                    .read_view::<u8>(VmOffset::new(info.vaddr), info.filesz)
                    .ok_or_else(|| ParsePhdrError::malformed("PT_TLS image is malformed"))?,
            )
        } else {
            None
        };

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
                dt_debug_addr: dynamic.dt_debug_addr,
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
                symtab,
            },
            module: ElfCore {
                inner: Arc::new(CoreInner {
                    is_init: AtomicBool::new(false),
                    path,
                    exports: exports_handle(exports),
                    finalizer: OnceCell::new(),
                    user_data,
                    dynamic_info: Some(Arc::new(DynamicInfo {
                        eh_frame_hdr,
                        phdrs,
                        soname,
                        #[cfg(feature = "lazy-binding")]
                        lazy: LazyBindingInfo::new(dynamic.pltrel.clone(), lazy_symtab),
                    })),
                    tls: CoreTlsState::new(
                        tls_mod_id,
                        tls_tp_offset,
                        tls_info,
                        tls_image,
                        Tls::unregister,
                        Tls::init_tls,
                        Tls::tls_get_addr,
                    ),
                    tls_desc_args: CoreTlsDescArgs::default(),
                    segments,
                }),
            },
        })
    }

    /// Creates a relocation builder for this dynamic image.
    pub fn relocator(self) -> Relocator<Self, (), (), Arch> {
        Relocator::<(), (), (), Arch>::new().with_object(self)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
    /// Build a dynamic image from the intermediate loader state.
    pub(crate) fn from_builder<Tls>(
        mut builder: ImageBuilder<Tls, D, Arch, R>,
        phdrs: &[ElfPhdr<Arch::Layout>],
    ) -> Result<Self>
    where
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
        Self::from_parts::<Tls>(parts)
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
        args: RelocateArgs<'_, Arch, PreH, PostH, Obs>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        self.relocate_impl::<_, _, _>(args)
    }
}
