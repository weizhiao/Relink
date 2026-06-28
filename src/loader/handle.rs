use crate::{
    MmapError, Result,
    arch::NativeArch,
    observer::LoadObserver,
    os::{DefaultMmap, Mmap, PageSize},
    relocation::RelocationArch,
    runtime::{CodeExecutor, NativeCodeExecutor},
    sync::Arc,
    tls::TlsResolver,
};
#[cfg(feature = "object")]
use crate::{
    elf::ElfHeader,
    image::RawObject,
    input::ElfReader,
    memory::RegionAccess,
    object::{ObjectSections, SectionGroups},
    observer::{AfterObjectLoadEvent, BeforeObjectLoadEvent},
    relocation::ObjectRelocationArch,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

#[inline]
fn native_executor<Arch: RelocationArch>() -> Arc<dyn CodeExecutor<Arch>> {
    Arc::from(Box::new(NativeCodeExecutor) as Box<dyn CodeExecutor<Arch>>)
}

/// Configurable ELF loader.
///
/// `Loader` maps ELF objects from files or memory and produces raw image types such as
/// [`crate::image::RawElf`], [`crate::image::RawDynamic`], [`crate::image::RawDylib`],
/// and [`crate::image::RawExec`].
/// Those raw images can then be relocated by calling `.relocator().relocate()`.
///
/// Use the `with_*` builder methods to customize hooks, lifecycle handling,
/// dynamic-image user data, memory mapping, and TLS behavior.
///
/// # Examples
///
/// ```no_run
/// use elf_loader::Loader;
///
/// let mut loader = Loader::new();
/// let raw = loader.load_dylib("path/to/liba.so").unwrap();
/// let lib = raw.relocator().relocate().unwrap();
/// ```
pub struct Loader<Obs = (), D: 'static = (), Tls = (), Arch = NativeArch, M = DefaultMmap>
where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    pub(super) buf: super::ElfBuf,
    pub(super) inner: LoaderInner<Obs, D, Arch, M>,
    _marker: PhantomData<(Tls, Arch)>,
}

pub(super) struct LoaderInner<Obs, D: 'static, Arch: RelocationArch, M: Mmap = DefaultMmap> {
    mapper: M,
    pub(super) observer: Obs,
    pub(super) executor: Arc<dyn CodeExecutor<Arch>>,
    page_size: Option<PageSize>,
    force_static_tls: bool,
    #[cfg(feature = "object")]
    object_groups: Arc<SectionGroups>,
    _marker: PhantomData<fn() -> (D, Arch)>,
}

impl<Obs, D, Arch, M> LoaderInner<Obs, D, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: 'static,
    Arch: RelocationArch,
    M: Mmap,
{
    #[inline]
    pub(crate) fn force_static_tls(&self) -> bool {
        self.force_static_tls
    }

    #[inline]
    pub(crate) fn mapper(&self) -> &M {
        &self.mapper
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

    #[cfg(feature = "object")]
    pub(crate) fn object_load_context(&mut self) -> (Arc<SectionGroups>, &mut Obs, &M) {
        (
            Arc::clone(&self.object_groups),
            &mut self.observer,
            &self.mapper,
        )
    }
}

impl Loader<(), (), (), NativeArch> {
    /// Creates a new [`Loader`] with the default mmap backend, no observer, no
    /// custom user data, no TLS resolver, and the host target architecture
    /// ([`NativeArch`]).
    ///
    /// To target a different ELF architecture (e.g. load an x86-64 shared
    /// object on a RISC-V host), switch the target architecture with
    /// [`for_arch::<NewArch>()`](Self::for_arch); the `e_machine` gate
    /// then validates against `NewArch::MACHINE` automatically.
    pub fn new() -> Self {
        Self {
            buf: super::ElfBuf::new(),
            inner: LoaderInner {
                // `DefaultMmap` is a unit struct only for some cfg-selected backends.
                #[allow(clippy::default_constructed_unit_structs)]
                mapper: DefaultMmap::default(),
                observer: (),
                executor: native_executor::<NativeArch>(),
                page_size: None,
                force_static_tls: false,
                #[cfg(feature = "object")]
                object_groups: Arc::new(SectionGroups::default()),
                _marker: PhantomData,
            },
            _marker: PhantomData,
        }
    }
}

impl Default for Loader<(), (), (), NativeArch> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Obs, D, Tls, Arch, M> Loader<Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    #[inline]
    pub(crate) fn mapper(&self) -> &M {
        self.inner.mapper()
    }

    #[inline]
    pub(crate) fn force_static_tls(&self) -> bool {
        self.inner.force_static_tls()
    }

    #[inline]
    pub(crate) fn executor(&self) -> Arc<dyn CodeExecutor<Arch>> {
        self.inner.executor.clone()
    }

    #[cfg(feature = "object")]
    #[inline]
    pub(crate) fn page_size(&self) -> Result<PageSize> {
        self.inner.page_size()
    }

    #[cfg(feature = "object")]
    pub(crate) fn notify_before_object_load(
        &mut self,
        ehdr: &ElfHeader<Arch::Layout>,
        sections: &mut ObjectSections<Arch::Layout>,
        object: &dyn ElfReader,
        user_data: &mut D,
    ) -> Result<()> {
        self.inner
            .observer
            .on_before_object_load(BeforeObjectLoadEvent::new(
                ehdr, sections, object, user_data,
            ))
    }

    #[cfg(feature = "object")]
    pub(crate) fn object_load_context(&mut self) -> (Arc<SectionGroups>, &mut Obs, &M) {
        self.inner.object_load_context()
    }

    #[cfg(feature = "object")]
    pub(crate) fn notify_after_object_load<R: RegionAccess>(
        &mut self,
        raw: &mut RawObject<D, Arch, R, Tls>,
    ) -> Result<()>
    where
        Arch: ObjectRelocationArch,
    {
        self.inner
            .observer
            .on_after_object_load(AfterObjectLoadEvent::new(raw))
    }

    /// Consumes the current loader and returns a new one with the specified
    /// dynamic-image user data type.
    ///
    /// Dynamic images are created with `NewD::default()`. To fill or adjust
    /// that data after dynamic metadata has been parsed, implement
    /// [`LoadObserver::on_after_dynamic_load`] on the configured load observer.
    pub fn with_data<NewD>(self) -> Loader<Obs, NewD, Tls, Arch, M>
    where
        NewD: Default + 'static,
        Obs: LoadObserver<NewD, Arch>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                observer: self.inner.observer,
                executor: self.inner.executor,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                #[cfg(feature = "object")]
                object_groups: self.inner.object_groups,
                _marker: PhantomData,
            },
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified
    /// load observer.
    pub fn with_observer<NewObs>(self, observer: NewObs) -> Loader<NewObs, D, Tls, Arch, M>
    where
        NewObs: LoadObserver<D, Arch>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                observer,
                executor: self.inner.executor,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                #[cfg(feature = "object")]
                object_groups: self.inner.object_groups,
                _marker: PhantomData,
            },
            _marker: PhantomData,
        }
    }

    /// Overrides the base page size used for segment layout decisions.
    ///
    /// By default, the loader uses [`Mmap::page_size`]. An override is useful
    /// for special runtimes and tests, but it must remain compatible with the
    /// mapping backend and with every loaded ELF's `PT_LOAD` alignment.
    pub fn with_page_size(mut self, page_size: PageSize) -> Self {
        self.inner.page_size = Some(page_size);
        self
    }

    /// Overrides the runtime-code executor used for init, fini and IFUNC.
    pub fn with_executor<E>(mut self, executor: E) -> Self
    where
        E: CodeExecutor<Arch>,
    {
        self.inner.executor = Arc::from(Box::new(executor) as Box<dyn CodeExecutor<Arch>>);
        self
    }

    /// Sets object section layout groups for subsequent relocatable-object loads.
    #[cfg(feature = "object")]
    pub fn with_object_section_groups(mut self, groups: SectionGroups) -> Self {
        self.inner.object_groups = Arc::new(groups);
        self
    }

    /// Consumes the current loader and returns a new one with the specified TLS resolver.
    pub fn with_tls_resolver<NewTls>(self) -> Loader<Obs, D, NewTls, Arch, M>
    where
        NewTls: TlsResolver<Arch>,
    {
        Loader {
            buf: self.buf,
            inner: self.inner,
            _marker: PhantomData,
        }
    }

    /// Sets whether to force static TLS for all loaded modules.
    pub fn with_static_tls(mut self, enabled: bool) -> Self {
        self.inner.force_static_tls = enabled;
        self
    }
}

impl<Obs, D, Tls, M> Loader<Obs, D, Tls, NativeArch, M>
where
    Obs: LoadObserver<D, NativeArch>,
    D: 'static,
    Tls: TlsResolver<NativeArch>,
    M: Mmap,
{
    /// Consumes the current loader and returns a new one with the default TLS resolver.
    #[cfg(feature = "tls")]
    pub fn with_default_tls_resolver(
        self,
    ) -> Loader<Obs, D, crate::tls::DefaultTlsResolver, NativeArch, M> {
        Loader {
            buf: self.buf,
            inner: self.inner,
            _marker: PhantomData,
        }
    }
}

/// Cross-architecture builder step.
///
/// Switching the target architecture is only meaningful while the loader has
/// not yet been bound to a user-data type. The builder therefore exposes
/// [`Loader::for_arch`] only on loaders whose `D` is still `()`. Callers should
/// pick the target architecture first and attach the user-data type afterwards:
///
/// ```no_run
/// use elf_loader::Loader;
/// use elf_loader::arch::x86_64::relocation::X86_64Arch;
///
/// let _loader = Loader::new()
///     .for_arch::<X86_64Arch>()
///     .with_data::<()>();
/// ```
impl<Obs, Tls, Arch, M> Loader<Obs, (), Tls, Arch, M>
where
    Obs: LoadObserver<(), Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Returns a new loader with a custom `Mmap` backend.
    pub fn with_mmap<NewMmap>(self, mapper: NewMmap) -> Loader<Obs, (), Tls, Arch, NewMmap>
    where
        NewMmap: Mmap,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper,
                observer: self.inner.observer,
                executor: self.inner.executor,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                #[cfg(feature = "object")]
                object_groups: self.inner.object_groups,
                _marker: PhantomData,
            },
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one whose target
    /// architecture is `NewArch` instead of the previous `Arch`.
    ///
    /// This is the primary entry point for cross-architecture loading. Picking
    /// a non-host architecture (e.g.
    /// [`X86_64Arch`](crate::arch::x86_64::relocation::X86_64Arch)) makes
    /// every subsequent `load_*` call validate the ELF `e_machine` against
    /// `NewArch::MACHINE` instead of the host's, and stamps the resulting
    /// raw images with `NewArch` so [`Relocator::relocate`] uses the matching
    /// relocation numbering.
    ///
    /// Non-host architectures do not execute guest
    /// IFUNC resolvers, TLSDESC stubs, lazy-binding trampolines, and init
    /// arrays are *not* executed on the host CPU.
    ///
    /// # Builder ordering
    ///
    /// `for_arch` is only available before
    /// [`with_data`](Loader::with_data) has been called; instead, switch `Arch`
    /// first and then attach the user-data type once the target architecture is
    /// fixed.
    ///
    /// [`Relocator::relocate`]: crate::relocation::Relocator::relocate
    pub fn for_arch<NewArch>(self) -> Loader<Obs, (), Tls, NewArch, M>
    where
        NewArch: RelocationArch,
        Tls: TlsResolver<NewArch>,
        Obs: LoadObserver<(), NewArch>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                observer: self.inner.observer,
                executor: native_executor::<NewArch>(),
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                #[cfg(feature = "object")]
                object_groups: self.inner.object_groups,
                _marker: PhantomData,
            },
            _marker: PhantomData,
        }
    }
}
