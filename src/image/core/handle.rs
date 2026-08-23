use super::{ElfModule, defs::LazyLookup};
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, SymbolTable},
    image::{
        CoreRuntime, DynamicInfo, GlobalScope, LookupScope, Module, ModuleHandle, ModuleSearch,
        ModuleState, PltRelocInfo, SymbolExports,
    },
    input::{ModuleSourceId, PathBuf},
    memory::{HostRegion, MappedView, RegionAccess, VmAddr},
    relocation::{LookupOrder, RelocationArch, SymbolRegistry},
    runtime::{CodeExecutor, DomainId, NativeCodeExecutor},
    segment::ElfSegments,
    sync::{Arc, OnceCell, Weak, arc_unsize},
    tls::{CoreTlsState, TlsImageProvider, TlsImageSource, TlsResolver},
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

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    TlsImageProvider for ElfModule<D, Arch, R, Tls>
{
    fn with_tls_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.tls.with_image(f)
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
        scope: &LookupScope<Arch, Tls>,
        global: Option<&GlobalScope<Arch, Tls>>,
        symbols: Option<&Arc<SymbolRegistry<Arch, Tls>>>,
        order: LookupOrder,
    ) {
        if self.inner.runtime.lazy_values().is_none() {
            return;
        }
        let source = self.module_handle();
        assert!(
            self.inner
                .lazy_lookup
                .set(LazyLookup {
                    source: source.downgrade(),
                    scope: scope.downgrade(global),
                    symbols: symbols.map(Arc::downgrade),
                    order,
                })
                .is_ok(),
            "lazy lookup state must be installed only once",
        );
    }

    pub(crate) fn publish_tls(&self) -> Result<()> {
        if self.inner.tls.module().is_none() {
            return Ok(());
        }
        let provider = arc_unsize!(self.inner.clone() => dyn TlsImageProvider);
        self.inner
            .tls
            .publish(TlsImageSource::new(Arc::downgrade(&provider)))
    }

    #[inline]
    pub(crate) fn into_module_handle(self) -> crate::image::ModuleHandle<Arch, Tls> {
        crate::image::ModuleHandle::from_shared(arc_unsize!(self.inner => dyn Module<Arch, Tls>))
    }

    #[inline]
    pub(crate) fn module_handle(&self) -> crate::image::ModuleHandle<Arch, Tls> {
        crate::image::ModuleHandle::from_shared(
            arc_unsize!(Arc::clone(&self.inner) => dyn Module<Arch, Tls>),
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
> From<ElfCore<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
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
> From<&ElfCore<D, Arch, R, Tls>> for ModuleHandle<Arch, Tls>
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
        path: PathBuf,
        base: VmAddr,
        dynamic_entries: MappedView<ElfDyn<Arch::Layout>>,
        dynamic_addr: VmAddr,
        phdrs: Vec<ElfPhdr<Arch::Layout>>,
        eh_frame_hdr: Option<NonNull<u8>>,
        mut segments: ElfSegments<R>,
        tls: CoreTlsState<Arch, Tls>,
        user_data: D,
    ) -> Result<Self> {
        segments.set_base(base);
        let dynamic = ElfDynamic::<Arch>::new(dynamic_entries, dynamic_addr, &segments)?;
        let symtab = SymbolTable::from_dynamic(&dynamic, &segments)?;
        let exports = symtab.clone();
        let lazy_symtab = symtab.clone();
        let needed_libs = dynamic
            .needed_libs
            .iter()
            .map(|needed| symtab.strtab().get_str(needed.get()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let soname = dynamic
            .soname_off
            .map(|soname_off| symtab.strtab().get_str(soname_off.get()));
        let rpath = dynamic
            .rpath_off
            .map(|rpath_off| symtab.strtab().get_str(rpath_off));
        let runpath = dynamic
            .runpath_off
            .map(|runpath_off| symtab.strtab().get_str(runpath_off));
        let search = ModuleSearch::from_dynamic(path, soname, runpath, rpath);
        let lazy_plt = PltRelocInfo::new(dynamic.pltrel, lazy_symtab);
        let source = ModuleSourceId::fresh();
        let inner = Arc::new(ElfModule {
            runtime: Box::new(CoreRuntime::new::<D, R, Tls>(Some(lazy_plt))),
            executor: arc_unsize!(Arc::new(NativeCodeExecutor) => dyn CodeExecutor<Arch>),
            search,
            state: ModuleState::initialized(source, DomainId::PROCESS),
            lifecycle: OnceCell::new(),
            exports: arc_unsize!(Arc::new(exports) => dyn SymbolExports<Arch::Layout>),
            dynamic_info: Some(Arc::new(DynamicInfo::<Arch> {
                eh_frame_hdr,
                phdrs: ElfPhdrs::Vec(phdrs),
                needed_libs,
                symbolic: dynamic.symbolic,
            })),
            lazy_lookup: OnceCell::new(),
            tls,
            segments,
            user_data,
        });
        ElfModule::bind_runtime_owner(&inner);
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

#[cfg(test)]
mod tests {
    use super::*;

    struct NonCloneData;

    #[test]
    fn weak_core_ref_clone_does_not_require_user_data_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<ElfCoreRef<NonCloneData>>();
    }
}
