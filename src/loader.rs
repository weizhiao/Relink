use crate::{
    Result,
    elf::{EHDR_SIZE, ElfHeader, ElfPhdr, ElfShdr},
    image::{ImageBuilder, ObjectBuilder},
    input::ElfReader,
    os::{DefaultMmap, Mmap},
    segment::{ElfSegments, SegmentBuilder, program::ProgramSegments, section::SectionSegments},
    sync::Arc,
    tls::{DefaultTlsResolver, TlsResolver},
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::marker::PhantomData;

pub(crate) struct ElfBuf {
    buf: Vec<u8>,
}

impl ElfBuf {
    pub(crate) fn new() -> Self {
        let mut buf = Vec::new();
        buf.resize(EHDR_SIZE, 0);
        ElfBuf { buf }
    }

    pub(crate) fn prepare_ehdr(&mut self, object: &mut impl ElfReader) -> Result<ElfHeader> {
        object.read(&mut self.buf[..EHDR_SIZE], 0)?;
        ElfHeader::new(&self.buf).cloned()
    }

    pub(crate) fn prepare_phdrs(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<&[ElfPhdr]> {
        let (phdr_start, phdr_end) = ehdr.phdr_range();
        let size = phdr_end - phdr_start;
        if size > self.buf.len() {
            self.buf.resize(size, 0);
        }
        object.read(&mut self.buf[..size], phdr_start)?;
        unsafe {
            Ok(core::slice::from_raw_parts(
                self.buf.as_ptr().cast::<ElfPhdr>(),
                (phdr_end - phdr_start) / size_of::<ElfPhdr>(),
            ))
        }
    }

    pub(crate) fn prepare_shdrs_mut(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<&mut [ElfShdr]> {
        let (shdr_start, shdr_end) = ehdr.shdr_range();
        let size = shdr_end - shdr_start;
        if size > self.buf.len() {
            self.buf.resize(size, 0);
        }
        object.read(&mut self.buf[..size], shdr_start)?;
        unsafe {
            Ok(core::slice::from_raw_parts_mut(
                self.buf.as_mut_ptr().cast::<ElfShdr>(),
                (shdr_end - shdr_start) / size_of::<ElfShdr>(),
            ))
        }
    }
}

/// Context provided to hook functions during ELF loading.
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

/// Hook trait for processing program headers during loading.
///
/// # Examples
/// ```rust
/// use elf_loader::{LoadHook, LoadHookContext, Result};
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
pub struct FnContext<'a> {
    func: Option<fn()>,
    func_array: Option<&'a [fn()]>,
}

impl<'a> FnContext<'a> {
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

/// Handler trait for initialization and finalization functions.
pub trait FnHandler: Send + Sync {
    /// Executes the handler with the provided context.
    fn call(&self, ctx: &FnContext);
}

impl<F> FnHandler for F
where
    F: Fn(&FnContext) + Send + Sync,
{
    fn call(&self, ctx: &FnContext) {
        (self)(ctx)
    }
}

#[cfg(not(feature = "portable-atomic"))]
pub(crate) type DynFnHandler = Arc<dyn FnHandler>;
#[cfg(feature = "portable-atomic")]
pub(crate) type DynFnHandler = Arc<Box<dyn FnHandler>>;

/// Context provided to the user data generator.
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

/// The ELF object loader.
///
/// `Loader` is responsible for orchestrating the loading of ELF objects into memory.
///
/// # Examples
/// ```no_run
/// use elf_loader::{Loader, input::ElfBinary};
///
/// let mut loader = Loader::new();
/// let bytes = std::fs::read("liba.so").unwrap();
/// let lib = loader.load_dylib(ElfBinary::new("liba.so", &bytes)).unwrap();
/// ```
pub struct Loader<M = DefaultMmap, H = (), D = (), Tls = DefaultTlsResolver>
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
    init_fn: DynFnHandler,
    fini_fn: DynFnHandler,
    hook: H,
    force_static_tls: bool,
    user_data_loader: Box<dyn Fn(&UserDataLoaderContext) -> D>,
}

impl Loader<DefaultMmap, (), (), DefaultTlsResolver> {
    /// Creates a new `Loader` with default settings.
    pub fn new() -> Self {
        #[cfg(not(feature = "portable-atomic"))]
        let c_abi: DynFnHandler = Arc::new(|ctx: &FnContext| {
            ctx.func()
                .iter()
                .chain(ctx.func_array().unwrap_or(&[]).iter())
                .for_each(|init| unsafe { core::mem::transmute::<_, &extern "C" fn()>(init) }());
        });
        #[cfg(feature = "portable-atomic")]
        let c_abi: DynFnHandler = Arc::new(Box::new(|ctx: &FnContext| {
            ctx.func()
                .iter()
                .chain(ctx.func_array().unwrap_or(&[]).iter())
                .for_each(|init| unsafe { core::mem::transmute::<_, &extern "C" fn()>(init) }());
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
        F: FnHandler + 'static,
    {
        #[cfg(not(feature = "portable-atomic"))]
        {
            self.inner.init_fn = Arc::new(init_fn);
        }
        #[cfg(feature = "portable-atomic")]
        {
            self.inner.init_fn = Arc::new(Box::new(init_fn));
        }
        self
    }

    /// Sets the finalization function handler.
    ///
    /// This handler is responsible for calling the finalization functions
    /// (e.g., `.fini` and `.fini_array`) of the loaded ELF object.
    pub fn with_fini<F>(mut self, fini_fn: F) -> Self
    where
        F: FnHandler + 'static,
    {
        #[cfg(not(feature = "portable-atomic"))]
        {
            self.inner.fini_fn = Arc::new(fini_fn);
        }
        #[cfg(feature = "portable-atomic")]
        {
            self.inner.fini_fn = Arc::new(Box::new(fini_fn));
        }
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

    /// Sets whether to force static TLS for all loaded modules.
    pub fn with_static_tls(mut self, enabled: bool) -> Self {
        self.inner.force_static_tls = enabled;
        self
    }

    /// Reads the ELF header.
    pub fn read_ehdr(&mut self, object: &mut impl ElfReader) -> Result<ElfHeader> {
        self.buf.prepare_ehdr(object)
    }

    /// Reads the program header table.
    pub fn read_phdr(
        &mut self,
        object: &mut impl ElfReader,
        ehdr: &ElfHeader,
    ) -> Result<&[ElfPhdr]> {
        self.buf.prepare_phdrs(ehdr, object)
    }
}

impl<H, D> LoaderInner<H, D>
where
    H: LoadHook,
    D: 'static,
{
    pub(crate) fn create_builder<M, Tls>(
        &mut self,
        ehdr: ElfHeader,
        phdrs: &[ElfPhdr],
        mut object: impl ElfReader,
    ) -> Result<ImageBuilder<'_, H, M, Tls, D>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let init_fn = self.init_fn.clone();
        let fini_fn = self.fini_fn.clone();
        let force_static_tls = self.force_static_tls;
        let mut phdr_segments =
            ProgramSegments::new(phdrs, ehdr.is_dylib(), object.as_fd().is_some());
        let segments = phdr_segments.load_segments::<M>(&mut object)?;
        phdr_segments.mprotect::<M>()?;

        let user_data = (self.user_data_loader)(&UserDataLoaderContext::new(
            object.file_name(),
            &ehdr,
            Some(phdrs),
            None,
        ));

        let builder = ImageBuilder::new(
            &mut self.hook,
            segments,
            object.file_name().to_owned(),
            ehdr,
            init_fn,
            fini_fn,
            force_static_tls,
            user_data,
        );
        Ok(builder)
    }

    pub(crate) fn create_object_builder<M, Tls>(
        &mut self,
        ehdr: ElfHeader,
        shdrs: &mut [ElfShdr],
        mut object: impl ElfReader,
    ) -> Result<ObjectBuilder<Tls, D>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let init_fn = self.init_fn.clone();
        let fini_fn = self.fini_fn.clone();
        let mut shdr_segments = SectionSegments::new(shdrs, &mut object);
        let segments = shdr_segments.load_segments::<M>(&mut object)?;
        let pltgot = shdr_segments.take_pltgot();
        let mprotect = Box::new(move || {
            shdr_segments.mprotect::<M>()?;
            Ok(())
        });
        let user_data = (self.user_data_loader)(&UserDataLoaderContext::new(
            object.file_name(),
            &ehdr,
            None,
            Some(shdrs),
        ));

        let builder: ObjectBuilder<Tls, D> = ObjectBuilder::new(
            object.file_name().to_owned(),
            shdrs,
            init_fn,
            fini_fn,
            segments,
            mprotect,
            pltgot,
            user_data,
        );

        Ok(builder)
    }
}
