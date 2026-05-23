use super::{ElfCore, ElfCoreRef};
use crate::{
    Result,
    arch::ArchKind,
    elf::{
        ElfDyn, ElfDynamicTag, ElfPhdr, ElfProgramType, ElfSymbol, PreCompute, SymbolInfo,
        SymbolTable,
    },
    image::{Module, ModuleHandle, ModuleScope},
    input::{Path, PathBuf},
    os::{HostRegion, MappedRegion, MappedView, Mapper, RegionAccess, VmAddr, VmOffset},
    relocation::RelocationArch,
    segment::ElfSegments,
    tls::{TlsInfo, TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::vec::Vec;
use core::{any::Any, ffi::c_void, fmt::Debug, marker::PhantomData, ptr::NonNull};
use elf::abi::DF_STATIC_TLS;

/// A fully loaded and relocated ELF module with retained dependencies.
///
/// This is the common loaded representation used by relocated dylibs, dynamic
/// [`crate::image::LoadedExec`] values, and loaded object-file images.
pub struct LoadedCore<
    D: 'static = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) core: ElfCore<D, Arch, R>,
    pub(crate) deps: ModuleScope<Arch>,
}

/// Iterator over the loaded-library dependencies retained by a [`LoadedCore`].
pub struct LoadedDeps<
    'a,
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    modules: &'a [ModuleHandle<Arch>],
    next: usize,
    remaining: usize,
    _marker: PhantomData<fn() -> (D, R)>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> LoadedDeps<'a, D, Arch, R> {
    #[inline]
    fn new(modules: &'a [ModuleHandle<Arch>]) -> Self {
        let remaining = modules
            .iter()
            .filter(|module| module.as_any().is::<LoadedCore<D, Arch, R>>())
            .count();
        Self {
            modules,
            next: 0,
            remaining,
            _marker: PhantomData,
        }
    }

    /// Returns the number of loaded dependencies remaining in this iterator.
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining
    }

    /// Returns whether this iterator has no loaded dependencies remaining.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> Iterator
    for LoadedDeps<'a, D, Arch, R>
{
    type Item = &'a LoadedCore<D, Arch, R>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(module) = self.modules.get(self.next) {
            self.next += 1;
            if let Some(dep) = module.as_any().downcast_ref::<LoadedCore<D, Arch, R>>() {
                self.remaining -= 1;
                return Some(dep);
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> ExactSizeIterator
    for LoadedDeps<'_, D, Arch, R>
{
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Debug for LoadedCore<D, Arch, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedCore")
            .field("name", &self.core.name())
            .field("base", &format_args!("{}", self.core.base()))
            .field(
                "deps",
                &self
                    .deps()
                    .map(|d| d.name())
                    .collect::<alloc::vec::Vec<_>>(),
            )
            .finish()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> Clone for LoadedCore<D, Arch, R> {
    /// Clones the [`LoadedCore`], incrementing the reference count of its core and dependencies.
    fn clone(&self) -> Self {
        LoadedCore {
            core: self.core.clone(),
            deps: self.deps.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<&LoadedCore<D, Arch, R>>
    for LoadedCore<D, Arch, R>
{
    #[inline]
    fn from(module: &LoadedCore<D, Arch, R>) -> Self {
        module.clone()
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<LoadedCore<D, Arch, R>>
    for ModuleHandle<Arch>
{
    #[inline]
    fn from(module: LoadedCore<D, Arch, R>) -> Self {
        Self::new(module)
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> From<&LoadedCore<D, Arch, R>>
    for ModuleHandle<Arch>
{
    #[inline]
    fn from(module: &LoadedCore<D, Arch, R>) -> Self {
        Self::new(module.clone())
    }
}

impl<D: 'static, Arch: RelocationArch, R: RegionAccess> LoadedCore<D, Arch, R> {
    /// Wraps an [`ElfCore`] into a [`LoadedCore`] with no dependencies.
    ///
    /// # Safety
    ///
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core(core: ElfCore<D, Arch, R>) -> Self {
        LoadedCore {
            core,
            deps: ModuleScope::empty(),
        }
    }

    /// Returns an iterator over the loaded libraries this module depends on.
    pub fn deps(&self) -> LoadedDeps<'_, D, Arch, R> {
        LoadedDeps::new(self.deps.as_slice())
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

    /// Gets the length of the bounding runtime span covered by mapped memory.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.core.mapped_len()
    }

    /// Returns whether `addr` is inside one of this module's mapped slices.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
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
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch, R> {
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

    /// Creates a [`LoadedCore`] from an [`ElfCore`] and its retained dependencies.
    ///
    /// # Safety
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core_deps<S>(core: ElfCore<D, Arch, R>, deps: S) -> Self
    where
        S: Into<ModuleScope<Arch>>,
    {
        LoadedCore {
            core,
            deps: deps.into(),
        }
    }

    /// Returns a reference to the underlying [`ElfCore`].
    ///
    /// # Safety
    /// Lifecycle information is lost, so the dependencies of the current
    /// loaded object can be dropped too early if this reference is used carelessly.
    #[inline]
    pub unsafe fn core_ref(&self) -> &ElfCore<D, Arch, R> {
        &self.core
    }
}

impl<D: 'static, Arch: RelocationArch> LoadedCore<D, Arch> {
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
        let region = MappedRegion::local_alias(
            addr.as_mut_ptr::<c_void>(),
            byte_len,
            Mapper::from_munmap(|_, _| Ok(())),
        );
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
    pub unsafe fn new_unchecked<Tls: TlsResolver>(
        path: impl Into<PathBuf>,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        memory: (*mut c_void, usize),
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
        tls_tp_offset: Option<TlsTpOffset>,
        user_data: D,
    ) -> Result<Self> {
        let segments = ElfSegments::new(
            MappedRegion::local(
                memory.0,
                memory.1,
                Mapper::from_munmap(move |addr, len| unsafe { munmap(addr, len) }),
            ),
            VmAddr::from_ptr(memory.0),
            VmOffset::new(0),
        );
        let base = segments.base();
        let mut tls_mod_id = None;
        let mut actual_tls_tp_offset = tls_tp_offset;

        let mut dynamic = None;
        let mut eh_frame_hdr = None;
        let mut tls_phdr = None;
        let phdrs = phdrs.into();

        for phdr in &phdrs {
            match phdr.program_type() {
                ElfProgramType::DYNAMIC => {
                    dynamic = Some(Self::read_dynamic_view(&segments, base, phdr)?);
                }
                ElfProgramType::GNU_EH_FRAME => {
                    eh_frame_hdr = segments
                        .borrowed_ptr::<u8>(phdr.p_vaddr(), phdr.p_filesz())
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
            let info = TlsInfo::new(phdr, template.as_slice());

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
        Ok(Self {
            core: unsafe {
                ElfCore::from_raw(
                    path.into(),
                    base,
                    dynamic.ok_or(crate::ParsePhdrError::MissingDynamicSection)?,
                    phdrs,
                    eh_frame_hdr,
                    segments,
                    tls_mod_id,
                    actual_tls_tp_offset,
                    VmAddr::from_ptr(Tls::tls_get_addr as *const ()),
                    Tls::unregister,
                    user_data,
                )
            }?,
            deps: ModuleScope::empty(),
        })
    }

    /// Gets the symbol table
    pub fn symtab(&self) -> &SymbolTable<Arch::Layout> {
        &self.core.symtab()
    }
}

impl<D, Arch, R> Module<Arch> for LoadedCore<D, Arch, R>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn is_loaded(&self) -> bool {
        true
    }

    #[inline]
    fn name(&self) -> &str {
        LoadedCore::name(self)
    }

    #[inline]
    fn lookup_symbol<'source>(
        &'source self,
        symbol: &SymbolInfo<'_>,
        precompute: &mut PreCompute,
    ) -> Option<&'source ElfSymbol<Arch::Layout>> {
        self.core.symtab().lookup_filter(symbol, precompute)
    }

    #[inline]
    fn base(&self) -> VmAddr {
        self.core.base()
    }

    #[inline]
    fn read_bytes(&self, offset: VmOffset, dst: &mut [u8]) -> Result<()> {
        self.core.read_bytes(offset, dst)
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        self.core.host_ptr(addr)
    }

    #[inline]
    fn tls_mod_id(&self) -> Option<TlsModuleId> {
        LoadedCore::tls_mod_id(self)
    }

    #[inline]
    fn tls_tp_offset(&self) -> Option<TlsTpOffset> {
        LoadedCore::tls_tp_offset(self)
    }
}
