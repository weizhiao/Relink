use super::run::LoaderRun;
#[cfg(feature = "object")]
use crate::object::SectionGroups;
use crate::{
    MmapError, Result,
    arch::NativeArch,
    const_builder::NoDrop,
    os::{DefaultMmap, Mmap, PageSize},
    relocation::RelocationArch,
    runtime::{CodeExecutor, NativeCodeExecutor},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;
use core::{marker::PhantomData, mem::MaybeUninit, ptr};

#[inline]
pub(crate) fn native_executor<Arch: RelocationArch>() -> Arc<dyn CodeExecutor<Arch>> {
    Arc::from(Box::new(NativeCodeExecutor) as Box<dyn CodeExecutor<Arch>>)
}

/// Configurable ELF loader.
///
/// `Loader` maps ELF objects from files or memory and produces raw image types such as
/// [`crate::image::RawElf`], [`crate::image::RawDynamic`], [`crate::image::RawDylib`],
/// and [`crate::image::RawExec`].
/// Those raw images can then be relocated with [`crate::relocation::Relocator`].
///
/// Use the `with_*` builder methods to customize hooks, lifecycle handling,
/// dynamic-image user data, memory mapping, and TLS behavior.
///
/// # Examples
///
/// ```no_run
/// use elf_loader::{Loader, relocation::Relocator};
///
/// let mut loader = Loader::new();
/// let raw = loader.load_dylib("path/to/liba.so").unwrap();
/// let lib = Relocator::new().run(raw).relocate().unwrap();
/// ```
pub struct Loader<
    D: 'static = (),
    Tls = (),
    Arch = NativeArch,
    M = DefaultMmap,
    Exec = NativeCodeExecutor,
> where
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    mapper: M,
    executor: Exec,
    page_size: Option<PageSize>,
    force_static_tls: bool,
    _marker: PhantomData<fn() -> (D, Tls, Arch)>,
}

impl<D, Tls, Arch, M, Exec> Clone for Loader<D, Tls, Arch, M, Exec>
where
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap + Clone,
    Exec: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            mapper: self.mapper.clone(),
            executor: self.executor.clone(),
            page_size: self.page_size,
            force_static_tls: self.force_static_tls,
            _marker: PhantomData,
        }
    }
}

struct LoaderFields<M, Exec> {
    mapper: NoDrop<M>,
    executor: NoDrop<Exec>,
    page_size: Option<PageSize>,
    force_static_tls: bool,
}

impl<M, Exec> LoaderFields<M, Exec> {
    #[inline]
    const fn into_loader<D, Tls, Arch>(self) -> Loader<D, Tls, Arch, M, Exec>
    where
        D: 'static,
        Tls: TlsResolver<Arch>,
        Arch: RelocationArch,
        M: Mmap,
    {
        let Self {
            mapper,
            executor,
            page_size,
            force_static_tls,
        } = self;

        Loader {
            mapper: mapper.into_inner(),
            executor: executor.into_inner(),
            page_size,
            force_static_tls,
            _marker: PhantomData,
        }
    }

    #[inline]
    const fn with_executor<D, Tls, Arch, NewExec>(
        self,
        executor: NewExec,
    ) -> Loader<D, Tls, Arch, M, NewExec>
    where
        D: 'static,
        Tls: TlsResolver<Arch>,
        Arch: RelocationArch,
        M: Mmap,
        Exec: Copy,
    {
        let Self {
            mapper,
            page_size,
            force_static_tls,
            ..
        } = self;

        Loader {
            mapper: mapper.into_inner(),
            executor,
            page_size,
            force_static_tls,
            _marker: PhantomData,
        }
    }

    #[inline]
    const fn with_mapper<D, Tls, Arch, NewM>(self, mapper: NewM) -> Loader<D, Tls, Arch, NewM, Exec>
    where
        D: 'static,
        Tls: TlsResolver<Arch>,
        Arch: RelocationArch,
        NewM: Mmap,
        M: Copy,
    {
        let Self {
            executor,
            page_size,
            force_static_tls,
            ..
        } = self;

        Loader {
            mapper,
            executor: executor.into_inner(),
            page_size,
            force_static_tls,
            _marker: PhantomData,
        }
    }
}

impl Loader<(), (), NativeArch, DefaultMmap, NativeCodeExecutor> {
    /// Creates a new [`Loader`] with the default mmap backend, no observer, no
    /// custom user data, no TLS resolver, and the host target architecture
    /// ([`NativeArch`]).
    ///
    /// To target a different ELF architecture (e.g. load an x86-64 shared
    /// object on a RISC-V host), switch the target architecture with
    /// [`for_arch::<NewArch>()`](Self::for_arch); the `e_machine` gate
    /// then validates against `NewArch::MACHINE` automatically.
    #[inline]
    pub const fn new() -> Self {
        Self {
            mapper: DefaultMmap::new(),
            executor: NativeCodeExecutor,
            page_size: None,
            force_static_tls: false,
            _marker: PhantomData,
        }
    }
}

impl Default for Loader<(), (), NativeArch, DefaultMmap, NativeCodeExecutor> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<D, Tls, Arch, M, Exec> Loader<D, Tls, Arch, M, Exec>
where
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    #[inline]
    const fn into_fields(self) -> LoaderFields<M, Exec> {
        let this = MaybeUninit::new(self);
        let this = this.as_ptr();

        // SAFETY: `this` points at the fully initialized `self` stored inside
        // `MaybeUninit`, so every field read below is initialized and aligned.
        // The original `Loader` is intentionally not dropped; every owned
        // field that must survive is moved into `LoaderFields`. Helpers that
        // discard an old field require that old field to be `Copy`.
        unsafe {
            LoaderFields {
                mapper: NoDrop::read(ptr::addr_of!((*this).mapper)),
                executor: NoDrop::read(ptr::addr_of!((*this).executor)),
                page_size: ptr::read(ptr::addr_of!((*this).page_size)),
                force_static_tls: ptr::read(ptr::addr_of!((*this).force_static_tls)),
            }
        }
    }
}

impl<D, Tls, Arch, M, Exec> Loader<D, Tls, Arch, M, Exec>
where
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    #[inline]
    pub(crate) const fn mapper(&self) -> &M {
        &self.mapper
    }

    #[inline]
    pub(crate) const fn force_static_tls(&self) -> bool {
        self.force_static_tls
    }

    #[inline]
    pub(crate) fn executor(&self) -> Arc<dyn CodeExecutor<Arch>> {
        Arc::from(Box::new(self.executor.clone()) as Box<dyn CodeExecutor<Arch>>)
    }

    /// Starts a loader run with fresh ELF metadata scratch space.
    #[inline]
    pub fn run(&self) -> LoaderRun<'_, (), D, Tls, Arch, M, Exec> {
        LoaderRun {
            loader: self,
            observer: (),
            buf: super::ElfBuf::new(),
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

    /// Consumes the current loader and returns a new one with the specified
    /// dynamic-image user data type.
    ///
    /// Dynamic images are created with `NewD::default()`. To fill or adjust
    /// that data after dynamic metadata has been parsed, implement
    /// [`LoadObserver::on_after_dynamic_load`] on the configured load observer.
    pub const fn with_data<NewD>(self) -> Loader<NewD, Tls, Arch, M, Exec>
    where
        NewD: Default + 'static,
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

    /// Overrides the runtime-code executor used for init, fini and IFUNC.
    pub const fn with_executor<E>(self, executor: E) -> Loader<D, Tls, Arch, M, E>
    where
        E: CodeExecutor<Arch> + Clone,
        Exec: Copy,
    {
        self.into_fields().with_executor(executor)
    }

    /// Consumes the current loader and returns a new one with the specified TLS resolver.
    pub const fn with_tls_resolver<NewTls>(self) -> Loader<D, NewTls, Arch, M, Exec>
    where
        NewTls: TlsResolver<Arch>,
    {
        self.into_fields().into_loader()
    }

    /// Sets whether to force static TLS for all loaded modules.
    pub const fn with_static_tls(mut self, enabled: bool) -> Self {
        self.force_static_tls = enabled;
        self
    }
}

impl<D, Tls, M, Exec> Loader<D, Tls, NativeArch, M, Exec>
where
    D: 'static,
    Tls: TlsResolver<NativeArch>,
    M: Mmap,
    Exec: CodeExecutor<NativeArch> + Clone,
{
    /// Consumes the current loader and returns a new one with the default TLS resolver.
    #[cfg(feature = "tls")]
    pub const fn with_default_tls_resolver(
        self,
    ) -> Loader<D, crate::tls::DefaultTlsResolver, NativeArch, M, Exec> {
        self.into_fields().into_loader()
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
impl<Tls, Arch, M, Exec> Loader<(), Tls, Arch, M, Exec>
where
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Returns a new loader with a custom `Mmap` backend.
    pub const fn with_mmap<NewMmap>(self, mapper: NewMmap) -> Loader<(), Tls, Arch, NewMmap, Exec>
    where
        NewMmap: Mmap,
        M: Copy,
    {
        self.into_fields().with_mapper(mapper)
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
    pub const fn for_arch<NewArch>(self) -> Loader<(), Tls, NewArch, M, NativeCodeExecutor>
    where
        NewArch: RelocationArch,
        Tls: TlsResolver<NewArch>,
        Exec: Copy,
    {
        self.into_fields().with_executor(NativeCodeExecutor)
    }
}
