use super::{ElfCore, Symbol};
use crate::runtime::Domain;
use crate::{
    ParsePhdrError, Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfPhdr, ElfProgramType, ElfSymbol},
    image::{
        ExportTable, GlobalScope, LocalScope, Module, ModuleHandle, ModuleSearch, ModuleState,
        SymbolLookup, module::lookup_symbol,
    },
    input::{ModulePath, ModuleSourceId},
    memory::{HostRegion, ImageMemory, MappedRegion, MappedView, RegionAccess, VmAddr},
    relocation::{LookupOrder, RelocationArch, SymbolRegistry},
    segment::ElfSegments,
    sync::Arc,
    tls::{ImageTlsState, TlsModule, TlsRegistration, TlsResolver},
};
use alloc::vec::Vec;
use core::{ffi::c_void, fmt::Debug, ops::Deref};

/// A relocated ELF module that retains its lookup scope.
/// Used for shared libraries, dynamic executables, and object files.
/// Dereferences to [`ElfCore`] for ELF metadata.
pub struct LoadedCore<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    core: ElfCore<D, Arch, R, Tls>,
    scope: LocalScope<Arch>,
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
            .field("base", &format_args!("{}", self.core.segments().base()))
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

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<LoadedCore<D, Arch, R, Tls>> for ModuleHandle<Arch>
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
> From<&LoadedCore<D, Arch, R, Tls>> for ModuleHandle<Arch>
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
    ///
    /// This inherent method intentionally shadows the raw [`Module::initialize`]
    /// hook implemented by `LoadedCore` for dynamic dispatch.
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
        let domain = core.domain().id();
        LoadedCore {
            core,
            scope: LocalScope::empty(domain),
        }
    }

    /// Returns the relocation lookup scope retained by this module.
    #[inline]
    pub const fn scope(&self) -> &LocalScope<Arch> {
        &self.scope
    }

    /// Returns a mutable reference to the user-defined data.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        self.core.user_data_mut()
    }

    /// Looks up a function or variable by its exact exported name, without mangling.
    /// Returns `Ok(None)` when absent and an error when resolution fails.
    /// IFUNCs use the domain's executor. Names must not contain NUL bytes;
    /// this is not checked.
    ///
    /// # Safety
    /// `T` must match the symbol's type and calling convention.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader, Relocator};
    /// # let config = Loader::new();
    /// # use elf_loader::{AddressSpaceId, Domain};
    /// # let domain = Domain::native(AddressSpaceId::PROCESS);
    /// # let mut loader = config.run(domain);
    /// # let raw = loader.load_dylib(ElfBinary::new("target/liba.so", &[])).unwrap();
    /// # let lib = Relocator::new().run(raw).relocate().unwrap();
    /// unsafe {
    ///     let awesome_function = lib.get::<unsafe extern "C" fn(f64) -> f64>("awesome_function").expect("symbol lookup failed").unwrap();
    ///     awesome_function(0.42);
    /// }
    /// ```
    ///
    /// A static variable may also be loaded and inspected:
    /// ```no_run
    /// # use elf_loader::{input::ElfBinary, image::Symbol, Loader, Relocator};
    /// # let config = Loader::new();
    /// # use elf_loader::{AddressSpaceId, Domain};
    /// # let domain = Domain::native(AddressSpaceId::PROCESS);
    /// # let mut loader = config.run(domain);
    /// # let raw = loader.load_dylib(ElfBinary::new("target/liba.so", &[])).unwrap();
    /// # let lib = Relocator::new().run(raw).relocate().unwrap();
    /// unsafe {
    ///     let awesome_variable = lib.get::<*mut f64>("awesome_variable").expect("symbol lookup failed").unwrap();
    ///     **awesome_variable = 42.0;
    /// };
    /// ```
    #[inline]
    pub unsafe fn get<'lib, T>(
        &'lib self,
        name: impl AsRef<[u8]>,
    ) -> Result<Option<Symbol<'lib, T>>> {
        let addr = lookup_symbol(self, &mut SymbolLookup::new(name.as_ref()))?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }

    /// Looks up a versioned symbol, using the domain's executor for IFUNCs.
    /// Names must not contain NUL bytes; this is not checked.
    /// Versions are bytes without a trailing NUL.
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function
    /// or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use elf_loader::{Loader, Relocator, input::ElfFile};
    /// # let config = Loader::new();
    /// # use elf_loader::{AddressSpaceId, Domain};
    /// # let domain = Domain::native(AddressSpaceId::PROCESS);
    /// # let mut loader = config.run(domain);
    /// # let raw = loader.load_dylib(ElfFile::from_path("target/liba.so").unwrap()).unwrap();
    /// # let lib = Relocator::new().run(raw).relocate().unwrap();
    /// let symbol = unsafe { lib.get_version::<fn()>("function_name", "1.0").expect("symbol lookup failed").unwrap() };
    /// ```
    ///
    /// # Arguments
    /// * `name` - The name of the symbol to look up
    /// * `version` - The version of the symbol to look up
    ///
    /// # Returns
    /// * `Ok(Some(symbol))` - If the symbol is found
    /// * `Ok(None)` - If the symbol is not found
    /// * `Err(error)` - If symbol resolution fails
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<'lib, T>(
        &'lib self,
        name: impl AsRef<[u8]>,
        version: impl AsRef<[u8]>,
    ) -> Result<Option<Symbol<'lib, T>>> {
        let addr = lookup_symbol(
            self,
            &mut SymbolLookup::with_version(name.as_ref(), version.as_ref()),
        )?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }

    /// Creates a [`LoadedCore`] from an [`ElfCore`] and its retained relocation lookup scope.
    ///
    /// # Safety
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core_scope(core: ElfCore<D, Arch, R, Tls>, scope: LocalScope<Arch>) -> Self {
        core.set_lazy_lookup(&scope, None, None, LookupOrder::GlobalFirst);
        Self { core, scope }
    }

    pub(crate) unsafe fn from_relocated(
        core: ElfCore<D, Arch, R, Tls>,
        scope: LocalScope<Arch>,
        global: Option<&GlobalScope<Arch>>,
        symbols: Option<Arc<SymbolRegistry<Arch>>>,
        order: LookupOrder,
    ) -> Self {
        core.set_lazy_lookup(&scope, global, symbols.as_ref(), order);
        Self { core, scope }
    }

    #[inline]
    pub(crate) fn into_module_handle(self) -> ModuleHandle<Arch> {
        self.core.into_module_handle()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for LoadedCore<D, Arch, R, Tls>
{
    type Target = ElfCore<D, Arch, R, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, Tls: TlsResolver<Arch>>
    LoadedCore<D, Arch, HostRegion, Tls>
{
    fn read_dynamic_view(
        segments: &ElfSegments,
        phdr: &ElfPhdr<Arch::Layout>,
    ) -> Result<MappedView<ElfDyn<Arch::Layout>>> {
        let malformed = "PT_DYNAMIC is not directly readable from mapped segments";
        if let Some(view) =
            segments.read_view::<ElfDyn<Arch::Layout>>(phdr.p_vaddr(), phdr.p_filesz())
            && !view.is_empty()
        {
            return Ok(view);
        }

        let addr = segments.base() + phdr.p_vaddr();
        let byte_len = phdr.p_filesz();
        let region =
            unsafe { MappedRegion::local_alias_no_unmap(addr.as_mut_ptr::<c_void>(), byte_len) };
        let view = region
            .read_view::<ElfDyn<Arch::Layout>>(0, byte_len)
            .ok_or(ParsePhdrError::malformed(malformed))?;
        if view.is_empty() {
            return Err(ParsePhdrError::malformed(malformed).into());
        }
        Ok(view)
    }

    /// Wraps an existing loaded ELF mapping and takes ownership of its TLS registration.
    /// The registration is also released if construction fails.
    ///
    /// Preserve the original `source_id` for file-backed images; use an opaque ID
    /// for custom sources or [`ModuleSourceId::fresh`] for a new anonymous source.
    ///
    /// # Safety
    /// Metadata and segments must describe a valid, relocated image in `domain`.
    /// Any TLS registration must belong to that domain and refer to initialized
    /// storage. Its provider must retain the storage and runtime. Keep the mapping
    /// valid while derived views use it, including readable `PT_TLS` initialization
    /// bytes for the image's lifetime. No TLS template is published by this constructor.
    #[inline]
    pub unsafe fn new_unchecked(
        path: ModulePath,
        source_id: ModuleSourceId,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        segments: ElfSegments,
        domain: Domain<Arch, Tls>,
        tls: Option<TlsRegistration>,
        user_data: D,
    ) -> Result<Self> {
        let base = segments.base();
        let mut dynamic = None;
        let mut eh_frame_hdr = None;
        let mut tls_phdr = None;
        let phdrs = phdrs.into();

        for phdr in &phdrs {
            match phdr.program_type() {
                ElfProgramType::DYNAMIC => {
                    dynamic = Some((
                        base + phdr.p_vaddr(),
                        Self::read_dynamic_view(&segments, phdr)?,
                    ));
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

        let tls = match (tls_phdr, tls) {
            (Some(phdr), Some(registration)) => {
                registration.module().check_domain(domain.id())?;
                let image = if phdr.p_filesz() == 0 {
                    MappedView::empty()
                } else {
                    segments
                        .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or(ParsePhdrError::malformed(
                            "PT_TLS is not directly readable from mapped segments",
                        ))?
                };
                ImageTlsState::owned(registration, image)
            }
            (None, None) => ImageTlsState::empty(),
            _ => return Err(crate::TlsError::ModuleMismatch.into()),
        };
        let (dynamic_addr, dynamic) = dynamic.ok_or(ParsePhdrError::MissingDynamicSection)?;
        let core = unsafe {
            ElfCore::from_raw(
                path,
                source_id,
                dynamic,
                dynamic_addr,
                phdrs,
                eh_frame_hdr,
                segments,
                tls,
                domain,
                user_data,
            )
        }?;
        Ok(unsafe { Self::from_core(core) })
    }
}

impl<D, Arch, R, Tls> Module<Arch> for LoadedCore<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &[u8] {
        self.core.name()
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        self.core.search()
    }

    #[inline]
    fn exports(&self) -> &ExportTable<Arch::Layout> {
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
    fn tls(&self) -> Option<&TlsModule> {
        self.core.tls()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        Module::state(&*self.core)
    }

    #[inline]
    fn initialize(&self) -> Result<()> {
        Module::initialize(&*self.core)
    }

    #[inline]
    fn finalize(&self) -> Result<()> {
        Module::finalize(&*self.core)
    }
}
