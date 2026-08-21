use super::CoreInner;
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfDyn, ElfDynamic, ElfPhdr, ElfPhdrs, ElfSymbol, SymbolTable},
    image::{
        CoreRuntime, DynamicInfo, LookupScope, Module, ModuleSearch, ModuleState, PltRelocInfo,
        SymbolExports,
    },
    input::{ModuleSourceId, Path, PathBuf},
    memory::{HostRegion, ImageMemory, MappedView, RegionAccess, VmAddr},
    observer::LifecycleHandlers,
    relocation::{RelocationArch, SymbolRegistry},
    runtime::{CodeExecutor, DomainId, NativeCodeExecutor},
    segment::ElfSegments,
    sync::{Arc, OnceCell, Weak, arc_unsize},
    tls::{CoreTlsState, ModuleTls, TlsImageProvider, TlsImageSource, TlsResolver},
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, ptr::NonNull};

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
    inner: Weak<CoreInner<D, Arch, R, Tls>>,
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
    TlsImageProvider for CoreInner<D, Arch, R, Tls>
{
    fn with_tls_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.tls.with_image(f)
    }
}

/// Shared core state for a loaded ELF image.
///
/// `ElfCore` stores metadata, runtime exports, segments, TLS state, and lifecycle
/// handlers behind an [`Arc`]. Higher-level image wrappers delegate most common
/// operations to this type.
pub struct ElfCore<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    /// Shared reference to the inner component data.
    pub(crate) inner: Arc<CoreInner<D, Arch, R, Tls>>,
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
    /// Runs this ELF module's initialization lifecycle at most once.
    #[inline]
    pub fn initialize(&self) -> Result<()> {
        self.inner
            .state
            .initialize(|| Module::initialize(&*self.inner))
    }

    /// Installs lifecycle behavior resolved during relocation.
    #[inline]
    pub(crate) fn set_lifecycle(&self, lifecycle: LifecycleHandlers) {
        assert!(
            self.inner.lifecycle.set(lifecycle).is_ok(),
            "lifecycle must be set only once",
        );
    }

    /// Creates a weak reference to this ELF core.
    #[inline]
    pub fn downgrade(&self) -> ElfCoreRef<D, Arch, R, Tls> {
        ElfCoreRef {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Gets user data from the ELF object
    #[inline]
    pub fn user_data(&self) -> &D {
        &self.inner.user_data
    }

    /// Returns the program headers of the ELF object.
    pub fn phdrs(&self) -> Option<&[ElfPhdr<Arch::Layout>]> {
        self.inner
            .dynamic_info
            .as_ref()
            .map(|info| info.phdrs.as_slice())
    }

    /// Returns a mutable reference to the user-defined data.
    #[inline]
    pub fn user_data_mut(&mut self) -> Option<&mut D> {
        Arc::get_mut(&mut self.inner).map(|inner| &mut inner.user_data)
    }

    /// Gets the number of strong references to the ELF object
    #[inline]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Gets the number of weak references to the ELF object
    #[inline]
    pub fn weak_count(&self) -> usize {
        Arc::weak_count(&self.inner)
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.inner.search.path()
    }

    /// Gets the base address of the ELF object
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.inner.segments.base()
    }

    /// Returns the DT_SONAME value when this core has dynamic metadata.
    #[inline]
    pub(crate) fn soname(&self) -> Option<&str> {
        self.inner.search.soname()
    }

    /// Returns the `DT_NEEDED` names retained from the dynamic section.
    #[inline]
    pub fn needed_libs(&self) -> &[&str] {
        self.inner
            .dynamic_info
            .as_ref()
            .map_or(&[], |info| info.needed_libs.as_ref())
    }

    /// Returns whether dynamic relocations in this image prefer definitions from itself.
    #[inline]
    pub(crate) fn symbolic(&self) -> bool {
        self.inner
            .dynamic_info
            .as_ref()
            .is_some_and(|info| info.symbolic)
    }

    /// Installs the retained relocation lookup scope for this core.
    #[inline]
    pub(crate) fn set_scope(&self, scope: &LookupScope<Arch, Tls>) {
        assert!(
            self.inner.scope.set(scope.downgrade()).is_ok(),
            "relocation scope must be installed only once",
        );
    }

    #[inline]
    pub(crate) fn set_symbol_registry(&self, symbols: &Arc<SymbolRegistry<Arch, Tls>>) {
        assert!(
            self.inner.symbols.set(Arc::downgrade(symbols)).is_ok(),
            "symbol registry must be installed only once",
        );
    }

    /// Returns the mapped segments owned by this image.
    #[inline]
    pub fn segments(&self) -> &ElfSegments<R> {
        &self.inner.segments
    }

    /// Gets the EH frame header pointer
    #[inline]
    pub fn eh_frame_hdr(&self) -> Option<NonNull<u8>> {
        self.inner
            .dynamic_info
            .as_ref()
            .and_then(|info| info.eh_frame_hdr)
    }

    #[inline]
    pub(crate) fn tls_resolver(&self) -> &Tls {
        self.inner.tls.resolver()
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
    pub(crate) fn executor(&self) -> &dyn CodeExecutor<Arch> {
        self.inner.executor.as_ref()
    }

    #[inline]
    pub(crate) fn into_module_handle(self) -> crate::image::ModuleHandle<Arch, Tls> {
        crate::image::ModuleHandle::new(self)
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
        let inner = Arc::new(CoreInner {
            runtime: Box::new(CoreRuntime::new::<D, R, Tls>(Some(lazy_plt))),
            executor: arc_unsize!(Arc::new(NativeCodeExecutor) => dyn CodeExecutor<Arch>),
            domain: DomainId::PROCESS,
            source_id: ModuleSourceId::fresh(),
            search,
            state: ModuleState::initialized(),
            lifecycle: OnceCell::new(),
            exports: arc_unsize!(Arc::new(exports) => dyn SymbolExports<Arch::Layout>),
            dynamic_info: Some(Arc::new(DynamicInfo::<Arch> {
                eh_frame_hdr,
                phdrs: ElfPhdrs::Vec(phdrs),
                needed_libs,
                symbolic: dynamic.symbolic,
            })),
            scope: OnceCell::new(),
            symbols: OnceCell::new(),
            tls,
            segments,
            user_data,
        });
        CoreInner::bind_runtime_owner(&inner);
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
            .field("base", &format_args!("{}", self.base()))
            .field("tls", &self.tls())
            .finish()
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls> Module<Arch, Tls> for ElfCore<D, Arch, R, Tls>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &str {
        self.inner.name()
    }

    #[inline]
    fn domain_id(&self) -> DomainId {
        self.inner.domain_id()
    }

    #[inline]
    fn source_id(&self) -> ModuleSourceId {
        self.inner.source_id()
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        self.inner.search()
    }

    #[inline]
    fn exports(&self) -> &dyn SymbolExports<Arch::Layout> {
        self.inner.exports()
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        self.segments()
    }

    #[inline]
    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr> {
        self.inner.resolve_symbol(symbol)
    }

    #[inline]
    fn tls(&self) -> Option<ModuleTls> {
        self.inner.tls()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        &self.inner.state
    }

    #[inline]
    fn initialize(&self) -> Result<()> {
        Module::initialize(&*self.inner)
    }

    #[inline]
    fn finalize(&self) -> Result<()> {
        Module::finalize(&*self.inner)
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
