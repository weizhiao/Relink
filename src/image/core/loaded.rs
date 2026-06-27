use super::{ElfCore, ElfCoreRef, Symbol};
use crate::{
    Result,
    arch::ArchKind,
    elf::{ElfDyn, ElfDynamicTag, ElfPhdr, ElfProgramType, ElfSymbol, ElfSymbolType},
    hint::unlikely,
    image::{Module, ModuleHandle, ModuleScope, ModuleScopeBuilder, ModuleTls, SymbolLookup},
    input::{Path, PathBuf},
    memory::{HostRegion, ImageMemory, MappedRegion, MappedView, RegionAccess, VmAddr, VmOffset},
    relocation::{RelocationArch, SymDef},
    segment::ElfSegments,
    tls::{TlsInfo, TlsResolver, TlsTpOffset},
};
use alloc::vec::Vec;
use core::{ffi::c_void, fmt::Debug, ptr::NonNull};
use elf::abi::DF_STATIC_TLS;

/// A fully loaded and relocated ELF module with a retained relocation lookup scope.
///
/// This is the common loaded representation used by relocated dylibs, dynamic
/// [`crate::image::LoadedExec`] values, and loaded object-file images.
pub struct LoadedCore<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    core: ElfCore<D, Arch, R, Tls>,
    scope: ModuleScope<Arch, Tls>,
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static> Debug
    for LoadedCore<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedCore")
            .field("name", &self.core.name())
            .field("base", &format_args!("{}", self.core.base()))
            .field(
                "scope",
                &self
                    .scope()
                    .iter()
                    .map(|module| module.name())
                    .collect::<alloc::vec::Vec<_>>(),
            )
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for LoadedCore<D, Arch, R, Tls>
{
    /// Clones the [`LoadedCore`], incrementing the reference count of its core and retained scope.
    fn clone(&self) -> Self {
        LoadedCore {
            core: self.core.clone(),
            scope: self.scope.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<&LoadedCore<D, Arch, R, Tls>> for LoadedCore<D, Arch, R, Tls>
{
    #[inline]
    fn from(module: &LoadedCore<D, Arch, R, Tls>) -> Self {
        module.clone()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static>
    From<LoadedCore<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(module: LoadedCore<D, Arch, R, Tls>) -> Self {
        Self::new(module)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static>
    From<&LoadedCore<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(module: &LoadedCore<D, Arch, R, Tls>) -> Self {
        Self::new(module.clone())
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> + 'static>
    LoadedCore<D, Arch, R, Tls>
{
    #[inline]
    pub(crate) fn from_relocated_core(core: ElfCore<D, Arch, R, Tls>) -> Self {
        LoadedCore {
            core,
            scope: ModuleScopeBuilder::<Arch, Tls>::new().into_scope(),
        }
    }

    /// Wraps an [`ElfCore`] into a [`LoadedCore`] with an empty retained scope.
    ///
    /// # Safety
    ///
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core(core: ElfCore<D, Arch, R, Tls>) -> Self {
        Self::from_relocated_core(core)
    }

    #[inline]
    pub(crate) fn from_relocated_core_scope(
        core: ElfCore<D, Arch, R, Tls>,
        scope: ModuleScope<Arch, Tls>,
    ) -> Self {
        LoadedCore { core, scope }
    }

    /// Returns the retained user-provided relocation lookup scope.
    #[inline]
    pub fn scope(&self) -> &[ModuleHandle<Arch, Tls>] {
        self.scope.as_slice()
    }

    /// Returns the target architecture used by this loaded module.
    #[inline]
    pub const fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.core.path()
    }

    /// Returns the ELF module identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the base address of the ELF object.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.core.base()
    }

    /// Returns the mapped segments owned by this module.
    #[inline]
    pub fn segments(&self) -> &ElfSegments<R> {
        self.core.segments()
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

    #[inline]
    fn lookup_addr(&self, sym: &ElfSymbol<Arch::Layout>) -> Option<VmAddr> {
        if unlikely(sym.symbol_type() == ElfSymbolType::TLS) {
            self.core.tls_addr(sym.st_value())
        } else {
            Some(SymDef::<Arch, Tls>::new(Some(sym), self).addr())
        }
    }

    /// Gets a pointer to a function or static variable by symbol name.
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
        let mut lookup = SymbolLookup::new(name);
        self.core
            .exports()
            .lookup(&mut lookup)
            .and_then(|sym| self.lookup_addr(sym))
            .map(|addr| Symbol::from_ptr(addr.as_mut_ptr()))
    }

    /// Load a versioned symbol from the ELF object.
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
        let mut lookup = SymbolLookup::with_version(name, version);
        self.core
            .exports()
            .lookup(&mut lookup)
            .and_then(|sym| self.lookup_addr(sym))
            .map(|addr| Symbol::from_ptr(addr.as_mut_ptr()))
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
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch, R, Tls> {
        self.core.downgrade()
    }

    /// Returns TLS metadata associated with this image.
    #[inline]
    pub fn tls(&self) -> ModuleTls {
        self.core.tls()
    }

    /// Creates a [`LoadedCore`] from an [`ElfCore`] and its retained relocation lookup scope.
    ///
    /// # Safety
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core_scope(
        core: ElfCore<D, Arch, R, Tls>,
        scope: ModuleScope<Arch, Tls>,
    ) -> Self {
        Self::from_relocated_core_scope(core, scope)
    }

    /// Returns a reference to the underlying [`ElfCore`].
    ///
    /// # Safety
    /// Lifecycle information is lost, so the retained scope of the current
    /// loaded object can be dropped too early if this reference is used carelessly.
    #[inline]
    pub unsafe fn core_ref(&self) -> &ElfCore<D, Arch, R, Tls> {
        &self.core
    }
}

impl<D: 'static, Arch: RelocationArch, Tls: TlsResolver<Arch>>
    LoadedCore<D, Arch, HostRegion, Tls>
{
    fn read_dynamic_view(
        segments: &ElfSegments,
        base: VmAddr,
        phdr: &ElfPhdr<Arch::Layout>,
    ) -> Result<MappedView<ElfDyn<Arch::Layout>>> {
        let malformed = "PT_DYNAMIC is not directly readable from mapped segments";
        if let Some(view) =
            segments.read_view::<ElfDyn<Arch::Layout>>(phdr.p_vaddr(), phdr.p_filesz())
            && !view.is_empty()
        {
            return Ok(view);
        }

        let addr = base + phdr.p_vaddr();
        let byte_len = phdr.p_filesz();
        let region = MappedRegion::local_alias_no_unmap(addr.as_mut_ptr::<c_void>(), byte_len);
        let view = region
            .read_view::<ElfDyn<Arch::Layout>>(0, byte_len)
            .ok_or(crate::ParsePhdrError::malformed(malformed))?;
        if view.is_empty() {
            return Err(crate::ParsePhdrError::malformed(malformed).into());
        }
        Ok(view)
    }

    /// Creates a new [`LoadedCore`] from raw parts without validation.
    ///
    /// # Safety
    /// The caller must ensure that the provided metadata, segments, and TLS values
    /// describe a valid loaded ELF image.
    ///
    /// # Arguments
    /// * `path` - Loader source path or caller-provided source identifier
    /// * `phdrs` - The program headers
    /// * `memory` - The mapped memory (pointer and length)
    /// * `munmap` - Function to unmap the memory
    /// * `tls_tp_offset` - TLS thread pointer offset
    /// * `user_data` - User-defined data to associate with the ELF
    ///
    /// # Returns
    /// A new [`LoadedCore`] instance
    #[inline]
    pub unsafe fn new_unchecked(
        path: impl Into<PathBuf>,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        memory: (*mut c_void, usize),
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
        tls_tp_offset: Option<TlsTpOffset>,
        user_data: D,
    ) -> Result<Self> {
        let segments = ElfSegments::new(
            MappedRegion::local_with_munmap(memory.0, memory.1, move |addr, len| unsafe {
                munmap(addr, len)
            }),
            VmAddr::from_ptr(memory.0),
            VmOffset::new(0),
        );
        let base = segments.base();
        let mut tls_mod_id = None;
        let mut actual_tls_tp_offset = tls_tp_offset;
        let mut core_tls_info = None;
        let mut core_tls_image = None;

        let mut dynamic = None;
        let mut dynamic_addr = None;
        let mut eh_frame_hdr = None;
        let mut tls_phdr = None;
        let phdrs = phdrs.into();

        for phdr in &phdrs {
            match phdr.program_type() {
                ElfProgramType::DYNAMIC => {
                    dynamic_addr = Some(base + phdr.p_vaddr());
                    dynamic = Some(Self::read_dynamic_view(&segments, base, phdr)?);
                }
                ElfProgramType::GNU_EH_FRAME => {
                    eh_frame_hdr = segments
                        .host_ptr_range(base + phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or(crate::ParsePhdrError::malformed(
                            "PT_GNU_EH_FRAME is not directly readable from mapped segments",
                        ))
                        .map(Some)?;
                }
                ElfProgramType::TLS => {
                    tls_phdr = Some(phdr);
                }
                _ => {}
            }
        }

        if let Some(phdr) = tls_phdr {
            let template = segments
                .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                .ok_or(crate::ParsePhdrError::malformed(
                    "PT_TLS image is malformed",
                ))?;
            let info = TlsInfo::new(phdr);
            core_tls_info = Some(info);
            core_tls_image = Some(template);

            let mut static_tls = actual_tls_tp_offset.is_some();
            if !static_tls && let Some(dynamic_entries) = dynamic.as_ref() {
                for dynamic in dynamic_entries.as_slice() {
                    let tag = dynamic.tag();
                    if tag == ElfDynamicTag::NULL {
                        break;
                    }
                    if tag == ElfDynamicTag::FLAGS && dynamic.value() & DF_STATIC_TLS as usize != 0
                    {
                        static_tls = true;
                        break;
                    }
                }
            }

            // The Tls::register will register the TLS module and return the ID.
            if static_tls {
                let (mid, _offset) = if let Some(offset) = actual_tls_tp_offset {
                    (Tls::add_static_tls(&info, offset)?, offset)
                } else {
                    let (mid, offset) = Tls::register_static(&info)?;
                    actual_tls_tp_offset = Some(offset);
                    (mid, offset)
                };
                tls_mod_id = Some(mid);
            } else {
                tls_mod_id = Some(Tls::register(&info)?);
            }
        }
        let core = unsafe {
            ElfCore::from_raw(
                path.into(),
                base,
                dynamic.ok_or(crate::ParsePhdrError::MissingDynamicSection)?,
                dynamic_addr.ok_or(crate::ParsePhdrError::MissingDynamicSection)?,
                phdrs,
                eh_frame_hdr,
                segments,
                tls_mod_id,
                actual_tls_tp_offset,
                core_tls_info,
                core_tls_image,
                user_data,
            )
        }?;
        core.init_tls()?;
        Ok(Self {
            core,
            scope: ModuleScopeBuilder::<Arch, Tls>::new().into_scope(),
        })
    }
}

impl<D, Arch, R, Tls> Module<Arch, Tls> for LoadedCore<D, Arch, R, Tls>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        LoadedCore::name(self)
    }

    #[inline]
    fn exports(&self) -> &dyn crate::image::SymbolExports<Arch::Layout> {
        self.core.exports()
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        self.core.segments()
    }

    #[inline]
    fn tls(&self) -> ModuleTls {
        LoadedCore::tls(self)
    }
}
