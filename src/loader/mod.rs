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
//! - [`UserDataLoaderContext`] for attaching user-defined metadata to loaded images
//! - `with_*` builder methods for swapping the memory-mapping backend or TLS resolver

mod buffer;
mod builder;
mod load;

use crate::{
    Result,
    elf::{ElfHeader, ElfPhdr, ElfShdr},
    os::{DefaultMmap, Mmap},
    segment::ElfSegments,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

#[cfg(feature = "tls")]
use crate::tls::DefaultTlsResolver;

pub(crate) use buffer::ElfBuf;
pub(crate) use builder::ImageBuilder;

/// Context passed to [`LoadHook`] while a program header is being processed.
pub struct LoadHookContext<'a> {
    name: &'a str,
    phdr: &'a ElfPhdr,
    segments: &'a ElfSegments,
}

impl<'a> LoadHookContext<'a> {
    pub(crate) fn new(name: &'a str, phdr: &'a ElfPhdr, segments: &'a ElfSegments) -> Self {
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
    pub fn phdr(&self) -> &ElfPhdr {
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
pub trait LoadHook {
    /// Executes the hook with the provided context.
    ///
    /// If an error is returned, the loading process will be aborted.
    fn call<'a>(&mut self, ctx: &'a LoadHookContext<'a>) -> Result<()>;
}

impl<F> LoadHook for F
where
    F: for<'a> FnMut(&'a LoadHookContext<'a>) -> Result<()>,
{
    fn call<'a>(&mut self, ctx: &'a LoadHookContext<'a>) -> Result<()> {
        (self)(ctx)
    }
}

impl LoadHook for () {
    fn call<'a>(&mut self, _ctx: &'a LoadHookContext<'a>) -> Result<()> {
        Ok(())
    }
}

/// Context provided to the initialization/finalization handler.
pub struct LifecycleContext<'a> {
    func: Option<fn()>,
    func_array: Option<&'a [fn()]>,
}

impl<'a> LifecycleContext<'a> {
    pub(crate) fn new(func: Option<fn()>, func_array: Option<&'a [fn()]>) -> Self {
        Self { func, func_array }
    }

    /// Returns the single initialization/finalization function.
    pub fn func(&self) -> Option<fn()> {
        self.func
    }

    /// Returns the array of initialization/finalization functions.
    pub fn func_array(&self) -> Option<&[fn()]> {
        self.func_array
    }
}

/// Handler trait for ELF lifecycle callbacks.
///
/// Implementations control how initialization functions such as `.init` / `.init_array`
/// and finalization functions such as `.fini` / `.fini_array` are invoked.
pub trait LifecycleHandler: Send + Sync {
    /// Executes the handler with the provided context.
    fn call(&self, ctx: &LifecycleContext);
}

impl<F> LifecycleHandler for F
where
    F: Fn(&LifecycleContext) + Send + Sync,
{
    fn call(&self, ctx: &LifecycleContext) {
        (self)(ctx)
    }
}

pub(crate) type DynLifecycleHandler = Arc<Box<dyn LifecycleHandler>>;

/// Context passed to [`Loader::with_context_loader`].
pub struct UserDataLoaderContext<'a> {
    /// The name of the ELF object being loaded.
    name: &'a str,
    /// The ELF header of the object.
    ehdr: &'a ElfHeader,
    /// The program headers of the object.
    phdrs: Option<&'a [ElfPhdr]>,
    /// The section headers of the object.
    shdrs: Option<&'a [ElfShdr]>,
}

impl<'a> UserDataLoaderContext<'a> {
    pub(crate) fn new(
        name: &'a str,
        ehdr: &'a ElfHeader,
        phdrs: Option<&'a [ElfPhdr]>,
        shdrs: Option<&'a [ElfShdr]>,
    ) -> Self {
        Self {
            name,
            ehdr,
            phdrs,
            shdrs,
        }
    }

    /// Returns the name of the ELF object being loaded.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Returns the ELF header of the object.
    pub fn ehdr(&self) -> &ElfHeader {
        self.ehdr
    }

    /// Returns the program headers of the object.
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
        self.phdrs
    }

    /// Returns the section headers of the object.
    pub fn shdrs(&self) -> Option<&[ElfShdr]> {
        self.shdrs
    }
}

/// Configurable ELF loader.
///
/// `Loader` maps ELF objects from files or memory and produces raw image types such as
/// [`crate::image::RawElf`], [`crate::image::RawDylib`], and [`crate::image::RawExec`].
/// Those raw images can then be relocated by calling `.relocator().relocate()`.
///
/// Use the `with_*` builder methods to customize hooks, lifecycle handling,
/// attached user data, memory mapping, and TLS behavior.
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
pub struct Loader<M = DefaultMmap, H = (), D = (), Tls = ()>
where
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    pub(crate) buf: ElfBuf,
    pub(crate) inner: LoaderInner<H, D>,
    _marker: PhantomData<(M, Tls)>,
}

pub(crate) struct LoaderInner<H, D> {
    init_fn: DynLifecycleHandler,
    fini_fn: DynLifecycleHandler,
    hook: H,
    force_static_tls: bool,
    user_data_loader: Box<dyn Fn(&UserDataLoaderContext) -> D>,
}

impl Loader<DefaultMmap, (), (), ()> {
    /// Creates a new [`Loader`] with the default mmap backend, no hook, no custom
    /// user data, and no TLS resolver.
    pub fn new() -> Self {
        let c_abi: DynLifecycleHandler = Arc::new(Box::new(|ctx: &LifecycleContext| {
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
                force_static_tls: false,
                user_data_loader: Box::new(|_| ()),
            },
            _marker: PhantomData,
        }
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    H: LoadHook,
    M: Mmap,
    D: 'static,
    Tls: TlsResolver,
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

    /// Consumes the current loader and returns a new one with the specified context data type.
    pub fn with_context<NewD>(self) -> Loader<M, H, NewD, Tls>
    where
        NewD: Default + 'static,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                init_fn: self.inner.init_fn,
                fini_fn: self.inner.fini_fn,
                hook: self.inner.hook,
                force_static_tls: self.inner.force_static_tls,
                user_data_loader: Box::new(|_| NewD::default()),
            },
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified user data generator.
    pub fn with_context_loader<NewD>(
        self,
        loader: impl Fn(&UserDataLoaderContext) -> NewD + 'static,
    ) -> Loader<M, H, NewD, Tls>
    where
        NewD: 'static,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                init_fn: self.inner.init_fn,
                fini_fn: self.inner.fini_fn,
                hook: self.inner.hook,
                force_static_tls: self.inner.force_static_tls,
                user_data_loader: Box::new(loader),
            },
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified hook.
    pub fn with_hook<NewHook>(self, hook: NewHook) -> Loader<M, NewHook, D, Tls>
    where
        NewHook: LoadHook,
    {
        Loader {
            buf: self.buf,
            inner: LoaderInner {
                init_fn: self.inner.init_fn,
                fini_fn: self.inner.fini_fn,
                hook,
                force_static_tls: self.inner.force_static_tls,
                user_data_loader: self.inner.user_data_loader,
            },
            _marker: PhantomData,
        }
    }

    /// Returns a new loader with a custom `Mmap` implementation.
    pub fn with_mmap<NewMmap: Mmap>(self) -> Loader<NewMmap, H, D, Tls> {
        Loader {
            buf: self.buf,
            inner: self.inner,
            _marker: PhantomData,
        }
    }

    /// Consumes the current loader and returns a new one with the specified TLS resolver.
    #[cfg(feature = "tls")]
    pub fn with_tls_resolver<NewTls>(self) -> Loader<M, H, D, NewTls>
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
    pub fn with_default_tls_resolver(self) -> Loader<M, H, D, DefaultTlsResolver> {
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
