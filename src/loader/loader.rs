use super::{
    LifecycleContext, LifecycleHandler, LoadHook, SharedLifecycleHandler, shared_lifecycle_handler,
};
use crate::{
    MmapError, Result,
    arch::NativeArch,
    image::RawDynamic,
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
pub struct Loader<H = (), D: 'static = (), Tls = (), Arch = NativeArch>
where
    H: LoadHook<Arch::Layout>,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    pub(crate) buf: super::ElfBuf,
    pub(crate) inner: LoaderInner<H, D, Arch>,
    _marker: PhantomData<(Tls, Arch)>,
}

pub(crate) struct LoaderInner<H, D: 'static, Arch: RelocationArch> {
    pub(crate) mapper: Mapper,
    pub(crate) init_fn: SharedLifecycleHandler,
    pub(crate) fini_fn: SharedLifecycleHandler,
    pub(crate) hook: H,
    pub(crate) page_size: Option<PageSize>,
    pub(crate) force_static_tls: bool,
    pub(crate) dynamic_initializer: Box<dyn FnMut(&mut RawDynamic<D, Arch>) -> Result<()>>,
}

impl<H, D, Arch> LoaderInner<H, D, Arch>
where
    H: LoadHook<Arch::Layout>,
    D: 'static,
    Arch: RelocationArch,
{
    pub(crate) fn lifecycle_handlers(&self) -> (SharedLifecycleHandler, SharedLifecycleHandler) {
        (self.init_fn.clone(), self.fini_fn.clone())
    }

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
    /// Creates a new [`Loader`] with the default mmap backend, no hook, no custom
    /// user data, no TLS resolver, and the host target architecture
    /// ([`NativeArch`]).
    ///
    /// To target a different ELF architecture (e.g. load an x86-64 shared
    /// object on a RISC-V host), switch the target architecture with
    /// [`for_arch::<NewArch>()`](Self::for_arch); the `e_machine` gate
    /// then validates against `NewArch::MACHINE` automatically.
    pub fn new() -> Self {
        let c_abi: SharedLifecycleHandler =
            shared_lifecycle_handler(|ctx: &LifecycleContext<'_>| {
                ctx.func_addrs().for_each(|addr| {
                    let ptr = ctx
                    .segments()
                    .host_ptr(addr)
                    .expect(
                        "lifecycle function address is not backed by host-accessible mapped memory",
                    )
                    .as_ptr() as usize;
                    #[cfg(not(windows))]
                    unsafe {
                        core::mem::transmute::<usize, extern "C" fn()>(ptr)()
                    };
                    #[cfg(windows)]
                    unsafe {
                        core::mem::transmute::<usize, extern "sysv64" fn()>(ptr)()
                    };
                });
            });
        Self {
            buf: super::ElfBuf::new(),
            inner: LoaderInner {
                mapper: Mapper::new(DefaultMmap::default()),
                hook: (),
                init_fn: c_abi.clone(),
                fini_fn: c_abi,
                page_size: None,
                force_static_tls: false,
                dynamic_initializer: Box::new(|_| Ok(())),
            },
            _marker: PhantomData,
        }
    }
}

impl<H, D, Tls, Arch> Loader<H, D, Tls, Arch>
where
    H: LoadHook<Arch::Layout>,
    D: 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn mapper(&self) -> Mapper {
        self.inner.mapper()
    }

    /// Sets the initialization function handler.
    ///
    /// This handler is responsible for calling the initialization functions
    /// (e.g., `.init` and `.init_array`) of the loaded ELF object.
    ///
    /// Note: glibc passes `argc`, `argv`, and `envp` to functions in `.init_array`
    /// as a non-standard extension.
    pub fn with_init<F>(mut self, init_fn: F) -> Self
    where
        F: LifecycleHandler + 'static,
    {
        self.inner.init_fn = shared_lifecycle_handler(init_fn);
        self
    }

    /// Sets the finalization function handler.
    ///
    /// This handler is responsible for calling the finalization functions
    /// (e.g., `.fini` and `.fini_array`) of the loaded ELF object.
    pub fn with_fini<F>(mut self, fini_fn: F) -> Self
    where
        F: LifecycleHandler + 'static,
    {
        self.inner.fini_fn = shared_lifecycle_handler(fini_fn);
        self
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
    ) -> Loader<H, NewD, Tls, Arch>
    where
        NewD: Default + 'static,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                init_fn: self.inner.init_fn,
                fini_fn: self.inner.fini_fn,
                hook: self.inner.hook,
                page_size: self.inner.page_size,
                force_static_tls: self.inner.force_static_tls,
                dynamic_initializer: Box::new(initializer),
            },
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified hook.
    pub fn with_hook<NewHook>(self, hook: NewHook) -> Loader<NewHook, D, Tls, Arch>
    where
        NewHook: LoadHook<Arch::Layout>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                init_fn: self.inner.init_fn,
                fini_fn: self.inner.fini_fn,
                hook,
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
    pub fn with_tls_resolver<NewTls>(self) -> Loader<H, D, NewTls, Arch>
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
    pub fn with_default_tls_resolver(self) -> Loader<H, D, crate::tls::DefaultTlsResolver, Arch> {
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
impl<H, Tls, Arch> Loader<H, (), Tls, Arch>
where
    H: LoadHook<Arch::Layout>,
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
    pub fn for_arch<NewArch>(self) -> Loader<H, (), Tls, NewArch>
    where
        NewArch: RelocationArch,
        H: LoadHook<NewArch::Layout>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                mapper: self.inner.mapper,
                init_fn: self.inner.init_fn,
                fini_fn: self.inner.fini_fn,
                hook: self.inner.hook,
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
