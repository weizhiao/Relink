use crate::{
    MmapError, Result,
    arch::NativeArch,
    image::RawDynamic,
    observer::LoadObserver,
    os::{DefaultMmap, Mapper, Mmap, PageSize},
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

/// Configurable ELF loader.
///
/// `Loader` maps ELF objects from files or memory and produces raw image types such as
/// [`crate::image::RawElf`], [`crate::image::RawDynamic`], [`crate::image::RawDylib`],
/// and [`crate::image::RawExec`].
/// Those raw images can then be relocated by calling `.relocator().relocate()`.
///
/// Use the `with_*` builder methods to customize hooks, lifecycle handling,
/// dynamic-image initialization, memory mapping, and TLS behavior.
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
pub struct Loader<Obs = (), D: 'static = (), Tls = (), Arch = NativeArch>
where
    Obs: LoadObserver<Arch>,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    pub(crate) buf: super::ElfBuf,
    pub(crate) inner: LoaderInner<Obs, D, Arch>,
    _marker: PhantomData<(Tls, Arch)>,
}

pub(crate) struct LoaderInner<Obs, D: 'static, Arch: RelocationArch> {
    pub(crate) mapper: Mapper,
    pub(crate) observer: Obs,
    pub(crate) page_size: Option<PageSize>,
    pub(crate) force_static_tls: bool,
    pub(crate) dynamic_initializer: Box<dyn FnMut(&mut RawDynamic<D, Arch>) -> Result<()>>,
}

impl<Obs, D, Arch> LoaderInner<Obs, D, Arch>
where
    Obs: LoadObserver<Arch>,
    D: 'static,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn force_static_tls(&self) -> bool {
        self.force_static_tls
    }

    #[inline]
    pub(crate) fn mapper(&self) -> Mapper {
        self.mapper.clone()
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

    #[inline]
    pub(crate) fn initialize_dynamic(&mut self, dynamic: &mut RawDynamic<D, Arch>) -> Result<()> {
        (self.dynamic_initializer)(dynamic)
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
                mapper: Mapper::new(DefaultMmap::default()),
                observer: (),
                page_size: None,
                force_static_tls: false,
                dynamic_initializer: Box::new(|_| Ok(())),
            },
            _marker: PhantomData,
        }
    }
}

impl<Obs, D, Tls, Arch> Loader<Obs, D, Tls, Arch>
where
    Obs: LoadObserver<Arch>,
    D: 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn mapper(&self) -> Mapper {
        self.inner.mapper()
    }

    /// Consumes the current loader and returns a new one with the specified
    /// dynamic-image user data type and initializer.
    ///
    /// Dynamic images are first created with `NewD::default()`. The initializer
    /// then receives the completed raw image so it can fill or adjust the user
    /// data using dynamic metadata such as dependencies, run paths, and mapped
    /// addresses.
    pub fn with_dynamic_initializer<NewD>(
        self,
        initializer: impl FnMut(&mut RawDynamic<NewD, Arch>) -> Result<()> + 'static,
    ) -> Loader<Obs, NewD, Tls, Arch>
    where
        NewD: Default + 'static,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                observer: self.inner.observer,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                dynamic_initializer: Box::new(initializer),
            },
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified
    /// load observer.
    pub fn with_observer<NewObs>(self, observer: NewObs) -> Loader<NewObs, D, Tls, Arch>
    where
        NewObs: LoadObserver<Arch>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                observer,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                dynamic_initializer: self.inner.dynamic_initializer,
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

    /// Returns a new loader with a custom `Mmap` backend value.
    pub fn with_mmap<NewMmap: Mmap>(self, mapper: NewMmap) -> Self {
        let mut inner = self.inner;
        inner.mapper = Mapper::new(mapper);
        Loader {
            buf: self.buf,
            inner,
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified TLS resolver.
    #[cfg(feature = "tls")]
    pub fn with_tls_resolver<NewTls>(self) -> Loader<Obs, D, NewTls, Arch>
    where
        NewTls: TlsResolver,
    {
        Loader {
            buf: self.buf,
            inner: self.inner,
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the default TLS resolver.
    #[cfg(feature = "tls")]
    pub fn with_default_tls_resolver(self) -> Loader<Obs, D, crate::tls::DefaultTlsResolver, Arch> {
        Loader {
            buf: self.buf,
            inner: self.inner,
            _marker: PhantomData,
        }
    }

    /// Sets whether to force static TLS for all loaded modules.
    #[cfg(feature = "tls")]
    pub fn with_static_tls(mut self, enabled: bool) -> Self {
        self.inner.force_static_tls = enabled;
        self
    }
}

/// Cross-architecture builder step.
///
/// Switching the target architecture is only meaningful while the loader has
/// not yet been bound to a user-data type, because the dynamic initializer
/// borrows `RawDynamic<D, Arch>` and cannot be carried across an `Arch`
/// change. The builder therefore exposes [`Loader::for_arch`] only on
/// loaders whose `D` is still `()` (i.e. before
/// [`Loader::with_dynamic_initializer`] has been called). Callers should
/// pick the target architecture first and attach the user-data initializer
/// afterwards:
///
/// ```no_run
/// use elf_loader::Loader;
/// use elf_loader::arch::x86_64::relocation::X86_64Arch;
///
/// let _loader = Loader::new()
///     .for_arch::<X86_64Arch>()
///     .with_dynamic_initializer::<()>(|_| Ok(()));
/// ```
impl<Obs, Tls, Arch> Loader<Obs, (), Tls, Arch>
where
    Obs: LoadObserver<Arch>,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
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
    /// [`with_dynamic_initializer`](Loader::with_dynamic_initializer) has
    /// been called. The dynamic initializer's signature mentions `Arch`,
    /// so it cannot be retyped after the fact; instead, switch `Arch` first
    /// and then attach the initializer once the target architecture is fixed.
    ///
    /// [`Relocator::relocate`]: crate::relocation::Relocator::relocate
    pub fn for_arch<NewArch>(self) -> Loader<Obs, (), Tls, NewArch>
    where
        NewArch: RelocationArch,
        Obs: LoadObserver<NewArch>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                observer: self.inner.observer,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                // `D = ()` so the existing initializer is necessarily a
                // no-op; rebuilding a fresh no-op typed against `NewArch`
                // loses no information.
                dynamic_initializer: Box::new(|_| Ok(())),
            },
            _marker: PhantomData,
        }
    }
}
