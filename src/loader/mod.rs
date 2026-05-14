//! Loading entry points and customization hooks.
//!
//! This module centers on [`Loader`], the main entry point for mapping ELF inputs
//! into memory. A loader reads ELF metadata, maps segments, builds raw image types,
//! and prepares them for relocation.
//!
//! It also exposes the main customization points used during loading:
//!
//! - [`LoadHook`] for observing program headers as they are mapped
//! - [`LifecycleHandler`] for customizing `.init` / `.fini` invocation
//! - `with_dynamic_initializer` for initializing dynamic-image user data
//! - `with_*` builder methods for swapping the memory-mapping backend or TLS resolver

mod buffer;
mod builder;
mod load;

use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfLayout, ElfPhdr, Lifecycle, NativeElfLayout},
    image::RawDynamic,
    os::{DefaultMmap, Mmap, PageSize},
    relocation::RelocationArch,
    segment::ElfSegments,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

pub(crate) use buffer::ElfBuf;
pub(crate) use builder::{ImageBuilder, ScanBuilder};

/// Context passed to [`LoadHook`] while a program header is being processed.
pub struct LoadHookContext<'a, L: ElfLayout = NativeElfLayout> {
    name: &'a str,
    phdr: &'a ElfPhdr<L>,
    segments: &'a ElfSegments,
}

impl<'a, L: ElfLayout> LoadHookContext<'a, L> {
    pub(crate) fn new(name: &'a str, phdr: &'a ElfPhdr<L>, segments: &'a ElfSegments) -> Self {
        Self {
            name,
            phdr,
            segments,
        }
    }

    /// Returns the name of the ELF object being loaded.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Returns the program header for the current segment.
    pub fn phdr(&self) -> &ElfPhdr<L> {
        self.phdr
    }

    /// Returns the ELF segments.
    pub fn segments(&self) -> &ElfSegments {
        self.segments
    }
}

/// Hook trait for observing or vetoing segment loading.
///
/// Implement this trait to inspect program headers as the loader maps them into memory.
/// Returning an error aborts the load.
///
/// # Examples
///
/// ```rust
/// use elf_loader::{loader::{LoadHook, LoadHookContext}, Result};
///
/// struct MyHook;
///
/// impl LoadHook for MyHook {
///     fn call<'a>(&mut self, ctx: &'a LoadHookContext<'a>) -> Result<()> {
///         println!("Processing segment: {:?}", ctx.phdr());
///         Ok(())
///     }
/// }
/// ```
pub trait LoadHook<L: ElfLayout = NativeElfLayout> {
    /// Executes the hook with the provided context.
    ///
    /// If an error is returned, the loading process will be aborted.
    fn call<'a>(&mut self, ctx: &'a LoadHookContext<'a, L>) -> Result<()>;
}

impl<L, F> LoadHook<L> for F
where
    L: ElfLayout,
    F: for<'a> FnMut(&'a LoadHookContext<'a, L>) -> Result<()>,
{
    fn call<'a>(&mut self, ctx: &'a LoadHookContext<'a, L>) -> Result<()> {
        (self)(ctx)
    }
}

impl<L: ElfLayout> LoadHook<L> for () {
    fn call<'a>(&mut self, _ctx: &'a LoadHookContext<'a, L>) -> Result<()> {
        Ok(())
    }
}

/// Handler trait for ELF lifecycle callbacks.
///
/// Implementations control how initialization functions such as `.init` / `.init_array`
/// and finalization functions such as `.fini` / `.fini_array` are invoked.
pub trait LifecycleHandler: Send + Sync {
    /// Executes the handler with the provided context.
    fn call(&self, ctx: &Lifecycle<'_>);
}

impl<F> LifecycleHandler for F
where
    F: Fn(&Lifecycle<'_>) + Send + Sync,
{
    fn call(&self, ctx: &Lifecycle<'_>) {
        (self)(ctx)
    }
}

pub(crate) type DynLifecycleHandler = Arc<Box<dyn LifecycleHandler>>;

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
pub struct Loader<M = DefaultMmap, H = (), D: 'static = (), Tls = (), Arch = NativeArch>
where
    M: Mmap,
    H: LoadHook<Arch::Layout>,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    pub(crate) buf: ElfBuf,
    pub(crate) inner: LoaderInner<H, D, Arch>,
    _marker: PhantomData<(M, Tls, Arch)>,
}

pub(crate) struct LoaderInner<H, D: 'static, Arch: RelocationArch> {
    init_fn: DynLifecycleHandler,
    fini_fn: DynLifecycleHandler,
    hook: H,
    page_size: Option<PageSize>,
    force_static_tls: bool,
    dynamic_initializer: Box<dyn FnMut(&mut RawDynamic<D, Arch>) -> Result<()>>,
}

impl Loader<DefaultMmap, (), (), (), NativeArch> {
    /// Creates a new [`Loader`] with the default mmap backend, no hook, no custom
    /// user data, no TLS resolver, and the host relocation backend
    /// ([`NativeArch`]).
    ///
    /// To target a different ELF architecture (e.g. load an x86-64 shared
    /// object on a RISC-V host), switch the relocation backend with
    /// [`for_arch::<NewArch>()`](Self::for_arch); the `e_machine` gate
    /// then validates against `NewArch::MACHINE` automatically.
    pub fn new() -> Self {
        let c_abi: DynLifecycleHandler = Arc::new(Box::new(|ctx: &Lifecycle<'_>| {
            ctx.func()
                .iter()
                .chain(ctx.func_array().unwrap_or(&[]).iter())
                .for_each(|init| {
                    #[cfg(not(windows))]
                    unsafe {
                        core::mem::transmute::<_, &extern "C" fn()>(init)()
                    };
                    #[cfg(windows)]
                    unsafe {
                        core::mem::transmute::<_, &extern "sysv64" fn()>(init)()
                    };
                })
        }));
        Self {
            buf: ElfBuf::new(),
            inner: LoaderInner {
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

impl<M, H, D, Tls, Arch> Loader<M, H, D, Tls, Arch>
where
    H: LoadHook<Arch::Layout>,
    M: Mmap,
    D: 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
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
        self.inner.init_fn = Arc::new(Box::new(init_fn));
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
        self.inner.fini_fn = Arc::new(Box::new(fini_fn));
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
    ) -> Loader<M, H, NewD, Tls, Arch>
    where
        NewD: Default + 'static,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
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
    pub fn with_hook<NewHook>(self, hook: NewHook) -> Loader<M, NewHook, D, Tls, Arch>
    where
        NewHook: LoadHook<Arch::Layout>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
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

    /// Returns a new loader with a custom `Mmap` implementation.
    pub fn with_mmap<NewMmap: Mmap>(self) -> Loader<NewMmap, H, D, Tls, Arch> {
        Loader {
            buf: self.buf,
            inner: self.inner,
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified TLS resolver.
    #[cfg(feature = "tls")]
    pub fn with_tls_resolver<NewTls>(self) -> Loader<M, H, D, NewTls, Arch>
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
    pub fn with_default_tls_resolver(
        self,
    ) -> Loader<M, H, D, crate::tls::DefaultTlsResolver, Arch> {
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
/// Switching the relocation backend is only meaningful while the loader has
/// not yet been bound to a user-data type, because the dynamic initializer
/// borrows `RawDynamic<D, Arch>` and cannot be carried across an `Arch`
/// change. The builder therefore exposes [`Loader::for_arch`] only on
/// loaders whose `D` is still `()` (i.e. before
/// [`Loader::with_dynamic_initializer`] has been called). Callers should
/// pick the relocation backend first and attach the user-data initializer
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
impl<M, H, Tls, Arch> Loader<M, H, (), Tls, Arch>
where
    H: LoadHook<Arch::Layout>,
    M: Mmap,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    /// Consumes the current loader and returns a new one whose relocation
    /// backend is `NewArch` instead of the previous `Arch`.
    ///
    /// This is the primary entry point for cross-architecture loading. Picking
    /// a non-host backend (e.g.
    /// [`X86_64Arch`](crate::arch::x86_64::relocation::X86_64Arch)) makes
    /// every subsequent `load_*` call validate the ELF `e_machine` against
    /// `NewArch::MACHINE` instead of the host's, and stamps the resulting
    /// raw images with `NewArch` so [`Relocator::relocate`] uses the matching
    /// relocation numbering.
    ///
    /// Per-ISA backends report `SUPPORTS_NATIVE_RUNTIME == false`, so guest
    /// IFUNC resolvers, TLSDESC stubs, lazy-binding trampolines, and init
    /// arrays are *not* executed on the host CPU.
    ///
    /// # Builder ordering
    ///
    /// `for_arch` is only available before
    /// [`with_dynamic_initializer`](Loader::with_dynamic_initializer) has
    /// been called. The dynamic initializer's signature mentions `Arch`,
    /// so it cannot be retyped after the fact; instead, switch `Arch` first
    /// and then attach the initializer once the relocation backend is
    /// fixed.
    ///
    /// [`Relocator::relocate`]: crate::relocation::Relocator::relocate
    pub fn for_arch<NewArch>(self) -> Loader<M, H, (), Tls, NewArch>
    where
        NewArch: RelocationArch,
        H: LoadHook<NewArch::Layout>,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
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
