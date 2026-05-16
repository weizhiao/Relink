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
    relocation::{RelocAddr, RelocationArch},
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
pub struct LoadedCore<D: 'static = (), Arch: RelocationArch = crate::arch::NativeArch> {
    pub(crate) core: ElfCore<D, Arch>,
    pub(crate) deps: ModuleScope<Arch>,
}

/// Iterator over the loaded-library dependencies retained by a [`LoadedCore`].
pub struct LoadedDeps<'a, D: 'static, Arch: RelocationArch = crate::arch::NativeArch> {
    modules: &'a [ModuleHandle<Arch>],
    next: usize,
    remaining: usize,
    _marker: PhantomData<fn() -> D>,
}

impl<'a, D: 'static, Arch: RelocationArch> LoadedDeps<'a, D, Arch> {
    #[inline]
    fn new(modules: &'a [ModuleHandle<Arch>]) -> Self {
        let remaining = modules
            .iter()
            .filter(|module| module.as_any().is::<LoadedCore<D, Arch>>())
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

impl<'a, D: 'static, Arch: RelocationArch> Iterator for LoadedDeps<'a, D, Arch> {
    type Item = &'a LoadedCore<D, Arch>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(module) = self.modules.get(self.next) {
            self.next += 1;
            if let Some(dep) = module.as_any().downcast_ref::<LoadedCore<D, Arch>>() {
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

impl<D: 'static, Arch: RelocationArch> ExactSizeIterator for LoadedDeps<'_, D, Arch> {}

impl<D: 'static, Arch: RelocationArch> Debug for LoadedCore<D, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedCore")
            .field("name", &self.core.name())
            .field("base", &format_args!("0x{:x}", self.core.base()))
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

impl<D: 'static, Arch: RelocationArch> Clone for LoadedCore<D, Arch> {
    /// Clones the [`LoadedCore`], incrementing the reference count of its core and dependencies.
    fn clone(&self) -> Self {
        LoadedCore {
            core: self.core.clone(),
            deps: self.deps.clone(),
        }
    }
}

impl<D: 'static, Arch: RelocationArch> From<&LoadedCore<D, Arch>> for LoadedCore<D, Arch> {
    #[inline]
    fn from(module: &LoadedCore<D, Arch>) -> Self {
        module.clone()
    }
}

impl<D: 'static, Arch: RelocationArch> From<LoadedCore<D, Arch>> for ModuleHandle<Arch> {
    #[inline]
    fn from(module: LoadedCore<D, Arch>) -> Self {
        Self::new(module)
    }
}

impl<D: 'static, Arch: RelocationArch> From<&LoadedCore<D, Arch>> for ModuleHandle<Arch> {
    #[inline]
    fn from(module: &LoadedCore<D, Arch>) -> Self {
        Self::new(module.clone())
    }
}

impl<D: 'static, Arch: RelocationArch> LoadedCore<D, Arch> {
    /// Wraps an [`ElfCore`] into a [`LoadedCore`] with no dependencies.
    ///
    /// # Safety
    ///
    /// The caller must ensure the ELF object has been properly relocated.
    #[inline]
    pub unsafe fn from_core(core: ElfCore<D, Arch>) -> Self {
        LoadedCore {
            core,
            deps: ModuleScope::empty(),
        }
    }

    /// Returns an iterator over the loaded libraries this module depends on.
    pub fn deps(&self) -> LoadedDeps<'_, D, Arch> {
        LoadedDeps::new(self.deps.as_slice())
    }

    /// Returns the relocation backend used by this loaded module.
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
    pub fn base(&self) -> usize {
        self.core.base()
    }

    /// Gets the length of the bounding runtime span covered by mapped memory.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.core.mapped_len()
    }

    /// Returns whether `addr` is inside one of this module's mapped slices.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
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
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch> {
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
    pub unsafe fn from_core_deps<S>(core: ElfCore<D, Arch>, deps: S) -> Self
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
    pub unsafe fn core_ref(&self) -> &ElfCore<D, Arch> {
        &self.core
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
        let segments = ElfSegments::new(memory.0, memory.1, munmap);
        let base = segments.base();
        let mut tls_mod_id = None;
        let mut actual_tls_tp_offset = tls_tp_offset;

        let mut dynamic_ptr = core::ptr::null();
        let mut eh_frame_hdr = None;
        let mut tls_phdr = None;
        let phdrs = phdrs.into();

        for phdr in &phdrs {
            match phdr.program_type() {
                ElfProgramType::DYNAMIC => {
                    dynamic_ptr = base.wrapping_add(phdr.p_vaddr()) as *const ElfDyn<Arch::Layout>;
                }
                ElfProgramType::GNU_EH_FRAME => {
                    eh_frame_hdr = NonNull::new(base.wrapping_add(phdr.p_vaddr()) as *mut u8);
                }
                ElfProgramType::TLS => {
                    tls_phdr = Some(phdr);
                }
                _ => {}
            }
        }

        if let Some(phdr) = tls_phdr {
            unsafe {
                let template = core::slice::from_raw_parts(
                    base.wrapping_add(phdr.p_vaddr()) as *const u8,
                    phdr.p_filesz(),
                );
                let info = TlsInfo::new(phdr, core::mem::transmute(template));

                let mut static_tls = actual_tls_tp_offset.is_some();
                if !static_tls && !dynamic_ptr.is_null() {
                    let mut cur = dynamic_ptr;
                    loop {
                        let dynamic = &*cur;
                        let tag = dynamic.tag();
                        if tag == ElfDynamicTag::NULL {
                            break;
                        }
                        if tag == ElfDynamicTag::FLAGS
                            && dynamic.value() & DF_STATIC_TLS as usize != 0
                        {
                            static_tls = true;
                            break;
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
                    path.into(),
                    base,
                    dynamic_ptr,
                    phdrs,
                    eh_frame_hdr,
                    segments,
                    tls_mod_id,
                    actual_tls_tp_offset,
                    RelocAddr::from_ptr(Tls::tls_get_addr as *const ()),
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

impl<D, Arch> Module<Arch> for LoadedCore<D, Arch>
where
    D: 'static,
    Arch: RelocationArch,
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
    fn soname(&self) -> Option<&str> {
        self.core.soname()
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
    fn base_addr(&self) -> usize {
        self.base()
    }

    #[inline]
    fn segment_slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        Some(self.core.segment_slice(offset, len))
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
