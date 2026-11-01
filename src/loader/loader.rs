use super::run::LoaderRun;
use crate::{
    MmapError, Result,
    arch::NativeArch,
    const_builder::NoDrop,
    os::{DefaultMmap, Mmap, PageSize, ThpPolicy},
    relocation::RelocationArch,
    runtime::Domain,
    tls::TlsResolver,
};
#[cfg(feature = "object")]
use crate::{object::SectionGroups, sync::Arc};
use core::{marker::PhantomData, mem::MaybeUninit, ptr};

/// Reusable ELF loading configuration: architecture, memory mapper, and user-data type.
///
/// Bind a [`Domain`] with [`Loader::run`] to load files or memory. The resulting
/// raw images require relocation with [`crate::Relocator`]. Use [`crate::Linker`]
/// to load their `DT_NEEDED` dependencies automatically.
///
/// Observers and temporary loading state belong to [`LoaderRun`].
///
/// # Examples
///
/// ```no_run
/// use elf_loader::{Loader, Relocator};
///
/// let config = Loader::new();
/// use elf_loader::{AddressSpaceId, Domain};
/// let domain = Domain::native(AddressSpaceId::PROCESS);
/// let mut loader = config.run(domain);
/// let raw = loader.load_dylib("path/to/liba.so").unwrap();
/// let lib = Relocator::new().run(raw).relocate().unwrap();
/// ```
pub struct Loader<D: Send + Sync + 'static = (), Arch = NativeArch, M = DefaultMmap>
where
    Arch: RelocationArch,
    M: Mmap,
{
    mapper: M,
    page_size: Option<PageSize>,
    thp: Option<ThpPolicy>,
    force_static_tls: bool,
    _marker: PhantomData<fn() -> (D, Arch)>,
}

impl<D, Arch, M> Copy for Loader<D, Arch, M>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    M: Mmap + Copy,
{
}

struct LoaderFields<M> {
    mapper: NoDrop<M>,
    page_size: Option<PageSize>,
    thp: Option<ThpPolicy>,
    force_static_tls: bool,
}

impl<M> LoaderFields<M> {
    #[inline]
    const fn into_loader<D, Arch>(self) -> Loader<D, Arch, M>
    where
        D: Send + Sync + 'static,
        Arch: RelocationArch,
        M: Mmap,
    {
        let Self {
            mapper,
            page_size,
            thp,
            force_static_tls,
        } = self;
        Loader {
            mapper: mapper.into_inner(),
            page_size,
            thp,
            force_static_tls,
            _marker: PhantomData,
        }
    }

    #[inline]
    const fn with_mapper<D, Arch, NewM>(self, mapper: NewM) -> Loader<D, Arch, NewM>
    where
        D: Send + Sync + 'static,
        Arch: RelocationArch,
        NewM: Mmap,
        M: Copy,
    {
        let Self {
            page_size,
            thp,
            force_static_tls,
            ..
        } = self;
        Loader {
            mapper,
            page_size,
            thp,
            force_static_tls,
            _marker: PhantomData,
        }
    }
}

impl<D, Arch, M> Clone for Loader<D, Arch, M>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    M: Mmap + Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            mapper: self.mapper.clone(),
            page_size: self.page_size,
            thp: self.thp,
            force_static_tls: self.force_static_tls,
            _marker: PhantomData,
        }
    }
}

impl Loader<(), NativeArch, DefaultMmap> {
    /// Creates a loader for [`NativeArch`] with the default memory mapper and `()` user data.
    /// Use [`Self::with_arch`] to select another architecture.
    #[inline]
    pub const fn new() -> Self {
        Self {
            mapper: DefaultMmap::new(),
            page_size: None,
            thp: None,
            force_static_tls: false,
            _marker: PhantomData,
        }
    }
}

impl Default for Loader<(), NativeArch, DefaultMmap> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<D, Arch, M> Loader<D, Arch, M>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    M: Mmap,
{
    #[inline]
    const fn into_fields(self) -> LoaderFields<M> {
        let this = MaybeUninit::new(self);
        let this = this.as_ptr();
        unsafe {
            LoaderFields {
                mapper: NoDrop::read(ptr::addr_of!((*this).mapper)),

                page_size: ptr::read(ptr::addr_of!((*this).page_size)),
                thp: ptr::read(ptr::addr_of!((*this).thp)),
                force_static_tls: ptr::read(ptr::addr_of!((*this).force_static_tls)),
            }
        }
    }

    #[inline]
    pub(crate) const fn mapper(&self) -> &M {
        &self.mapper
    }

    #[inline]
    pub(crate) const fn force_static_tls(&self) -> bool {
        self.force_static_tls
    }

    #[inline]
    pub(super) const fn thp(&self) -> Option<ThpPolicy> {
        self.thp
    }

    /// Starts a loader run in a fixed runtime domain with fresh scratch space.
    /// The mapping backend must target the domain's address space.
    #[inline]
    pub fn run<Tls: TlsResolver<Arch>>(
        &self,
        domain: Domain<Arch, Tls>,
    ) -> LoaderRun<'_, (), D, Tls, Arch, M> {
        LoaderRun {
            loader: self,
            domain,
            observer: (),
            buf: super::ElfBuf::new(),
            search_paths: None,
            #[cfg(feature = "object")]
            object_groups: Arc::new(SectionGroups::default()),
        }
    }

    #[inline]
    pub(crate) fn page_size(&self) -> Result<PageSize> {
        let required = self.mapper.page_size();
        let page_size = self.page_size.unwrap_or(required);
        if page_size.bytes() < required.bytes()
            || !page_size.bytes().is_multiple_of(required.bytes())
        {
            return Err(MmapError::InvalidPageSize {
                configured: page_size.bytes(),
                required: required.bytes(),
            }
            .into());
        }

        Ok(page_size)
    }

    /// Sets the user-data type for dynamic images, initialized with `NewD::default()`.
    /// Populate it after parsing through
    /// [`LoadObserver::on_after_dynamic_load`](crate::observer::LoadObserver::on_after_dynamic_load).
    pub const fn with_data<NewD>(self) -> Loader<NewD, Arch, M>
    where
        NewD: Default + Send + Sync + 'static,
    {
        self.into_fields().into_loader()
    }

    /// Overrides the base page size used for segment layout decisions.
    ///
    /// By default, the loader uses [`Mmap::page_size`]. An override is useful
    /// for special runtimes and tests, but it must remain compatible with the
    /// mapping backend and with every loaded ELF's `PT_LOAD` alignment.
    pub const fn with_page_size(mut self, page_size: PageSize) -> Self {
        self.page_size = Some(page_size);
        self
    }

    /// Configures transparent huge pages for eligible file contents and anonymous BSS.
    ///
    /// No policy is configured by default, so no advice is sent. The policy
    /// applies after mapping to complete pages inside readable, non-writable
    /// LOAD file contents. Writable anonymous BSS always receives `MADV_HUGEPAGE`,
    /// including with [`ThpPolicy::Collapse`], before relocation and constructors.
    /// Sparse BSS usage may increase resident memory. Copied inputs, section arenas,
    /// and borrowed mappings are excluded. For overlapping LOADs, advice applies
    /// to the final mappings.
    ///
    /// [`ThpPolicy::Advise`] and [`ThpPolicy::Collapse`] take a target page size
    /// appropriate for the backend; no system policy is probed. The size must be
    /// a power of two larger than the base page size; otherwise no advice or
    /// additional alignment is requested. These policies may increase image
    /// alignment and choose a load bias that favors executable coverage, then
    /// total read-only coverage, while preserving ELF alignment requirements.
    /// Base page size, permissions, and relative segment layout are unchanged.
    /// The target size guides alignment and range selection; the kernel chooses
    /// the actual huge-page size.
    ///
    /// Mapping failures, including failure to satisfy increased alignment, are
    /// returned without retrying at a smaller alignment. Advice failures do not
    /// fail a load. See [`ThpPolicy`] for the effects of each policy.
    ///
    /// ```
    /// use elf_loader::{Loader, os::{PageSize, ThpPolicy}};
    ///
    /// let loader = Loader::new().with_thp(ThpPolicy::Advise(PageSize::Huge2MiB));
    /// ```
    pub const fn with_thp(mut self, policy: ThpPolicy) -> Self {
        self.thp = Some(policy);
        self
    }

    /// Sets whether to force static TLS for all loaded modules.
    pub const fn with_static_tls(mut self, enabled: bool) -> Self {
        self.force_static_tls = enabled;
        self
    }

    /// Returns a new loader with a custom `Mmap` backend.
    pub const fn with_mmap<NewMmap>(self, mapper: NewMmap) -> Loader<D, Arch, NewMmap>
    where
        NewMmap: Mmap,
        M: Copy,
    {
        self.into_fields().with_mapper(mapper)
    }

    /// Selects the architecture used to validate ELF headers and apply relocations.
    ///
    /// For non-native execution, provide a matching executor through [`Domain`]
    /// when calling [`Loader::run`].
    pub const fn with_arch<NewArch>(self) -> Loader<D, NewArch, M>
    where
        NewArch: RelocationArch,
    {
        self.into_fields().into_loader()
    }
}
