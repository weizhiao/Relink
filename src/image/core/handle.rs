use super::{ElfModule, defs::LazyLookup};
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, SymbolTable},
    image::{
        CoreRuntime, DynamicInfo, ExportTable, GlobalScope, LocalScope, Module, ModuleHandle,
        ModuleSearch, ModuleState,
    },
    input::{ModulePath, ModuleSourceId},
    memory::{HostRegion, MappedView, RegionAccess, VmAddr},
    relocation::{LookupOrder, RelocationArch, SymbolRegistry},
    runtime::Domain,
    segment::ElfSegments,
    sync::{Arc, OnceCell, Weak, arc_downgrade_unsize, arc_unsize},
    tls::{ImageTlsState, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, ops::Deref, ptr::NonNull};

/// A non-owning reference to an [`ElfCore`].
///
/// `ElfCoreRef` holds a weak reference to the shared core allocation. It is useful
/// when you want to avoid extending the lifetime of a loaded image unnecessarily
/// or need to detect when the image has been dropped.
pub struct ElfCoreRef<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Weak reference to the shared core allocation.
    inner: Weak<ElfModule<D, Arch, R, Tls>>,
}

// Keep this impl manual so cloning a weak core handle does not require D, Arch, or R to be Clone.
impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for ElfCoreRef<D, Arch, R, Tls>
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    ElfCoreRef<D, Arch, R, Tls>
{
    /// Attempts to upgrade the weak pointer to an [`ElfCore`].
    ///
    /// # Returns
    /// * `Some(ElfCore)` - If the component is still alive and the upgrade is successful.
    /// * `None` - If the [`ElfCore`] has been dropped.
    pub fn upgrade(&self) -> Option<ElfCore<D, Arch, R, Tls>> {
        self.inner.upgrade().map(|inner| ElfCore { inner })
    }
}

/// Typed owning handle for a shared [`ElfModule`].
///
/// Cloning this handle reuses the same module allocation. Read-only module and
/// ELF metadata methods are available through [`Deref`].
pub struct ElfCore<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Shared reference to the concrete module allocation.
    pub(crate) inner: Arc<ElfModule<D, Arch, R, Tls>>,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Clone
    for ElfCore<D, Arch, R, Tls>
{
    /// Clones the [`ElfCore`], incrementing the internal reference count.
    fn clone(&self) -> Self {
        ElfCore {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> ElfCore<D, Arch, R, Tls>
{
    /// Creates a weak reference to this ELF core.
    #[inline]
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch, R, Tls> {
        ElfCoreRef {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Returns a mutable reference to the user-defined data.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        Arc::get_mut(&mut self.inner).map(|inner| &mut inner.user_data)
    }

    /// Installs the weak state needed by lazy symbol lookup.
    #[inline]
    pub(crate) fn set_lazy_lookup(
        &self,
        scope: &LocalScope<Arch>,
        global: Option<&GlobalScope<Arch>>,
        symbols: Option<&Arc<SymbolRegistry<Arch>>>,
        order: LookupOrder,
    ) {
        if self.inner.runtime.lazy_values().is_none() {
            return;
        }
        assert!(
            self.inner
                .lazy_lookup
                .set(LazyLookup {
                    source: arc_downgrade_unsize!(&self.inner => dyn Module<Arch>),
                    scope: scope.downgrade(global),
                    symbols: symbols.map(Arc::downgrade),
                    order,
                })
                .is_ok(),
            "lazy lookup state must be installed only once",
        );
    }

    pub(crate) fn publish_tls(&self) -> Result<()> {
        let Some(module) = self.inner.tls.module() else {
            return Ok(());
        };
        self.inner
            .domain
            .tls_resolver()
            .publish(self.inner.tls.template()?, module.mod_id())
    }

    #[inline]
    pub(crate) fn into_module_handle(self) -> crate::image::ModuleHandle<Arch> {
        crate::image::ModuleHandle::from_shared(arc_unsize!(self.inner => dyn Module<Arch>))
    }

    #[inline]
    pub(crate) fn module_handle(&self) -> crate::image::ModuleHandle<Arch> {
        crate::image::ModuleHandle::from_shared(
            arc_unsize!(Arc::clone(&self.inner) => dyn Module<Arch>),
        )
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Deref
    for ElfCore<D, Arch, R, Tls>
{
    type Target = ElfModule<D, Arch, R, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<ElfCore<D, Arch, R, Tls>> for ModuleHandle<Arch>
{
    #[inline]
    fn from(core: ElfCore<D, Arch, R, Tls>) -> Self {
        core.into_module_handle()
    }
}

impl<
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
> From<&ElfCore<D, Arch, R, Tls>> for ModuleHandle<Arch>
{
    #[inline]
    fn from(core: &ElfCore<D, Arch, R, Tls>) -> Self {
        core.module_handle()
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    ElfCore<D, Arch, R, Tls>
{
    /// Creates an `ElfCore` from raw components.
    ///
    /// # Safety
    ///
    /// The caller must ensure these arguments describe a valid loaded dynamic ELF
    /// image and that all borrowed mapped views remain valid for the core's
    /// lifetime.
    #[allow(clippy::too_many_arguments)]
    pub(super) unsafe fn from_raw(
        path: ModulePath,
        source_id: ModuleSourceId,
        dynamic_entries: MappedView<ElfDyn<Arch::Layout>>,
        dynamic_addr: VmAddr,
        phdrs: Vec<ElfPhdr<Arch::Layout>>,
        eh_frame_hdr: Option<NonNull<u8>>,
        segments: ElfSegments<R>,
        tls: ImageTlsState,
        domain: Domain<Arch, Tls>,
        user_data: D,
    ) -> Result<Self> {
        let dynamic = ElfDynamic::<Arch>::new(dynamic_entries, dynamic_addr, &segments)?;
        let symtab = SymbolTable::from_dynamic(&dynamic, &segments)?;
        let needed_libs = dynamic
            .needed_libs
            .iter()
            .map(|needed| symtab.strtab().get_cstr(needed.get()).to_bytes())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let soname = dynamic
            .soname_off
            .map(|soname_off| symtab.strtab().get_cstr(soname_off.get()).to_bytes());
        let rpath = dynamic
            .rpath_off
            .map(|rpath_off| symtab.strtab().get_cstr(rpath_off).to_bytes());
        let runpath = dynamic
            .runpath_off
            .map(|runpath_off| symtab.strtab().get_cstr(runpath_off).to_bytes());
        let search = ModuleSearch::from_dynamic(path, soname, runpath, rpath);
        let inner = Arc::new_cyclic(|owner| ElfModule {
            runtime: CoreRuntime::new(owner, dynamic.pltrel),
            search,
            state: ModuleState::initialized(source_id, domain.id()),
            lifecycle: OnceCell::new(),
            exports: ExportTable::from_elf(symtab),
            dynamic_info: Some(Box::new(DynamicInfo::<Arch> {
                eh_frame_hdr,
                phdrs: ElfPhdrs::Vec(phdrs),
                needed_libs,
                symbolic: dynamic.symbolic,
            })),
            lazy_lookup: OnceCell::new(),
            tls,
            domain,
            segments,
            user_data,
        });
        Ok(Self { inner })
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> Debug
    for ElfCore<D, Arch, R, Tls>
{
    /// Formats the ElfCore for debugging purposes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfCore")
            .field("path", &self.inner.search.path())
            .field("base", &format_args!("{}", self.segments().base()))
            .field("tls", &self.tls())
            .finish()
    }
}
