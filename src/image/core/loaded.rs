use super::{ElfCore, ElfCoreRef, Symbol};
use crate::{
    ParsePhdrError, Result,
    arch::{ArchKind, NativeArch},
    elf::{ElfDyn, ElfDynamicTag, ElfPhdr, ElfProgramType, ElfSymbol},
    image::{
        LookupScope, Module, ModuleHandle, ModuleSearch, ModuleState, SymbolExports, SymbolLookup,
        module::lookup_symbol,
    },
    input::{ModuleSourceId, Path, PathBuf},
    memory::{HostRegion, ImageMemory, MappedRegion, MappedView, RegionAccess, VmAddr, VmOffset},
    relocation::{BindingDeps, RelocationArch, SymbolRegistry},
    runtime::DomainId,
    segment::ElfSegments,
    sync::Arc,
    tls::{CoreTlsState, ModuleTls, TlsInfo, TlsRequest, TlsResolver, TlsTpOffset},
};
use alloc::vec::Vec;
use core::{ffi::c_void, fmt::Debug, ptr::NonNull};
use elf::abi::DF_STATIC_TLS;

/// A fully loaded and relocated ELF module with a retained relocation lookup scope.
///
/// This is the common loaded representation used by relocated dylibs, dynamic
/// [`crate::image::LoadedExec`] values, and loaded object-file images.
pub struct LoadedCore<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    core: ElfCore<D, Arch, R, Tls>,
    scope: LookupScope<Arch, Tls>,
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> Debug for LoadedCore<D, Arch, R, Tls>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedCore")
            .field("name", &self.core.name())
            .field("base", &format_args!("{}", self.core.base()))
            .field("scope", &self.scope)
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
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

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    From<&LoadedCore<D, Arch, R, Tls>> for LoadedCore<D, Arch, R, Tls>
{
    #[inline]
    fn from(module: &LoadedCore<D, Arch, R, Tls>) -> Self {
        module.clone()
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<LoadedCore<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(module: LoadedCore<D, Arch, R, Tls>) -> Self {
        Self::new(module)
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<&LoadedCore<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn from(module: &LoadedCore<D, Arch, R, Tls>) -> Self {
        Self::new(module.clone())
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> LoadedCore<D, Arch, R, Tls>
{
    /// Runs this module's initialization lifecycle at most once.
    #[inline]
    pub fn initialize(&self) -> Result<()> {
        self.core.initialize()
    }

    /// Wraps an [`ElfCore`] into a [`LoadedCore`].
    ///
    /// # Safety
    ///
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core(core: ElfCore<D, Arch, R, Tls>) -> Self {
        let domain = core.domain_id();
        LoadedCore {
            core,
            scope: LookupScope::empty(domain),
        }
    }

    /// Returns the retained user-provided relocation lookup scope.
    #[inline]
    pub const fn scope(&self) -> &LookupScope<Arch, Tls> {
        &self.scope
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

    /// Returns the `DT_SONAME` value.
    #[inline]
    pub fn soname(&self) -> Option<&str> {
        self.core.soname()
    }

    /// Returns the `DT_NEEDED` names retained from the dynamic section.
    #[inline]
    pub fn needed_libs(&self) -> &[&str] {
        self.core.needed_libs()
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
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader, Relocator};
    /// # let mut loader = Loader::new();
    /// # let raw = loader.load_dylib(ElfBinary::new("target/liba.so", &[])).unwrap();
    /// # let lib = Relocator::new().run(raw).relocate().unwrap();
    /// unsafe {
    ///     let awesome_function = lib.get::<unsafe extern "C" fn(f64) -> f64>("awesome_function").unwrap();
    ///     awesome_function(0.42);
    /// }
    /// ```
    ///
    /// A static variable may also be loaded and inspected:
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader, Relocator};
    /// # let mut loader = Loader::new();
    /// # let raw = loader.load_dylib(ElfBinary::new("target/liba.so", &[])).unwrap();
    /// # let lib = Relocator::new().run(raw).relocate().unwrap();
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
        unsafe { self.try_get(name).ok().flatten() }
    }

    /// Tries to get a pointer to a function or static variable by symbol name.
    ///
    /// This resolves IFUNC symbols through the executor retained during relocation.
    ///
    /// # Safety
    ///
    /// `T` must match the type and ABI of the resolved symbol.
    #[inline]
    pub unsafe fn try_get<'lib, T>(&'lib self, name: &str) -> Result<Option<Symbol<'lib, T>>> {
        let addr = lookup_symbol(self, &mut SymbolLookup::new(name))?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }

    /// Load a versioned symbol from the ELF object.
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function
    /// or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{Loader, Relocator, input::ElfFile};
    /// # let mut loader = Loader::new();
    /// # let raw = loader.load_dylib(ElfFile::from_path("target/liba.so").unwrap()).unwrap();
    /// # let lib = Relocator::new().run(raw).relocate().unwrap();
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
        unsafe { self.try_get_version(name, version).ok().flatten() }
    }

    /// Tries to load a versioned symbol from the ELF object.
    ///
    /// This resolves IFUNC symbols through the executor retained during relocation.
    ///
    /// # Safety
    ///
    /// `T` must match the type and ABI of the resolved symbol.
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn try_get_version<'lib, T>(
        &'lib self,
        name: &str,
        version: &str,
    ) -> Result<Option<Symbol<'lib, T>>> {
        let addr = lookup_symbol(self, &mut SymbolLookup::with_version(name, version))?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
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

    /// Creates a [`LoadedCore`] from an [`ElfCore`] and its retained relocation lookup scope.
    ///
    /// # Safety
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core_scope(
        core: ElfCore<D, Arch, R, Tls>,
        scope: LookupScope<Arch, Tls>,
    ) -> Self {
        core.set_scope(&scope);
        Self {
            core,
            scope: scope.into_local(),
        }
    }

    pub(crate) unsafe fn from_relocated(
        core: ElfCore<D, Arch, R, Tls>,
        scope: LookupScope<Arch, Tls>,
        symbols: Option<Arc<SymbolRegistry<Arch, Tls>>>,
        bindings: BindingDeps<Arch, Tls>,
    ) -> Self {
        core.set_scope(&scope);
        bindings.install(core.state());
        if let Some(symbols) = &symbols {
            core.set_symbol_registry(symbols);
        }
        Self {
            core,
            scope: scope.into_local(),
        }
    }

    pub(crate) fn into_context_parts(self) -> (ModuleHandle<Arch, Tls>, LookupScope<Arch, Tls>) {
        let Self { core, scope } = self;
        (core.into_module_handle(), scope)
    }

    /// Returns a reference to the underlying [`ElfCore`].
    ///
    /// # Safety
    /// Lifecycle information is lost if this reference is used carelessly.
    #[inline]
    pub unsafe fn core_ref(&self) -> &ElfCore<D, Arch, R, Tls> {
        &self.core
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, Tls: TlsResolver<Arch>>
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
            .ok_or(ParsePhdrError::malformed(malformed))?;
        if view.is_empty() {
            return Err(ParsePhdrError::malformed(malformed).into());
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
        tls_resolver: Tls,
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
                        .ok_or(ParsePhdrError::malformed(
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

        let tls = if let Some(phdr) = tls_phdr {
            let template = segments
                .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                .ok_or(ParsePhdrError::malformed("PT_TLS image is malformed"))?;
            let info = TlsInfo::new(phdr);

            let mut static_tls = tls_tp_offset.is_some();
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

            let request = if let Some(offset) = tls_tp_offset {
                TlsRequest::Static(Some(offset))
            } else if static_tls {
                TlsRequest::Static(None)
            } else {
                TlsRequest::Dynamic
            };
            CoreTlsState::with_module(
                tls_resolver.clone(),
                tls_resolver.register(info, request)?,
                template,
            )
        } else {
            CoreTlsState::without_module(tls_resolver)
        };
        let core = unsafe {
            ElfCore::from_raw(
                path.into(),
                base,
                dynamic.ok_or(ParsePhdrError::MissingDynamicSection)?,
                dynamic_addr.ok_or(ParsePhdrError::MissingDynamicSection)?,
                phdrs,
                eh_frame_hdr,
                segments,
                tls,
                user_data,
            )
        }?;
        core.publish_tls()?;
        Ok(unsafe { Self::from_core(core) })
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> Module<Arch, Tls> for LoadedCore<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        self.core.name()
    }

    #[inline]
    fn domain_id(&self) -> DomainId {
        self.core.domain_id()
    }

    #[inline]
    fn source_id(&self) -> ModuleSourceId {
        self.core.source_id()
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        self.core.search()
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        self.core.exports()
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        self.core.segments()
    }

    #[inline]
    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr> {
        self.core.resolve_symbol(symbol)
    }

    #[inline]
    fn tls(&self) -> Option<ModuleTls> {
        self.core.tls()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        Module::state(&self.core)
    }

    #[inline]
    fn initialize(&self) -> Result<()> {
        Module::initialize(&self.core)
    }

    #[inline]
    fn finalize(&self) -> Result<()> {
        Module::finalize(&self.core)
    }
}
