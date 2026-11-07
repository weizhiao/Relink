use super::run::LoaderRun;
use crate::{
    arch::NativeArch,
    const_builder::NoDrop,
    os::{DefaultMmap, Mmap, ThpPolicy},
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
/// use elf_loader::{AddressSpaceId, Domain, Loader, Relocator};
///
/// let config = Loader::new();
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
            thp,
            force_static_tls,
        } = self;
        Loader {
            mapper: mapper.into_inner(),
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
            thp,
            force_static_tls,
            ..
        } = self;
        Loader {
            mapper,
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

    /// Sets the user-data type for dynamic images, initialized with `NewD::default()`.
    /// Populate it after parsing through
    /// [`LoadObserver::on_after_dynamic_load`](crate::observer::LoadObserver::on_after_dynamic_load).
    pub const fn with_data<NewD>(self) -> Loader<NewD, Arch, M>
    where
        NewD: Default + Send + Sync + 'static,
    {
        self.into_fields().into_loader()
    }

    /// Configures transparent huge pages for mapped or copied ELF images.
    ///
    /// No policy is configured by default. See [`ThpPolicy`] for which file,
    /// copied, and BSS ranges receive advice and when it is applied.
    /// Section arenas and borrowed mappings are excluded.
    ///
    /// The target size comes from [`Mmap::thp_page_size`]. If unavailable, the
    /// loader skips THP alignment and advice. Otherwise the policy may increase
    /// image alignment while preserving ELF alignment and relative segment layout.
    /// The kernel chooses the actual huge-page size; sparse usage may increase
    /// resident memory.
    ///
    /// Mapping failures, including failure to satisfy increased alignment, are
    /// returned without retrying at a smaller alignment. Advice failures do not
    /// fail a load.
    ///
    /// ```
    /// use elf_loader::{Loader, os::ThpPolicy};
    ///
    /// let loader = Loader::new().with_thp(ThpPolicy::Advise);
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
    /// Segment and section layouts use the backend's [`Mmap::page_size`].
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
