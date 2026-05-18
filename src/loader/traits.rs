use crate::{
    Result,
    elf::{ElfLayout, ElfPhdr, Lifecycle, NativeElfLayout},
    input::Path,
    os::VmAddr,
    segment::ElfSegments,
    sync::Arc,
};
use alloc::boxed::Box;
use core::ptr::NonNull;

/// Context passed to [`LoadHook`] while a program header is being processed.
pub struct LoadHookContext<'a, L: ElfLayout = NativeElfLayout> {
    path: &'a Path,
    phdr: &'a ElfPhdr<L>,
    segments: &'a ElfSegments,
}

impl<'a, L: ElfLayout> LoadHookContext<'a, L> {
    pub(crate) fn new(path: &'a Path, phdr: &'a ElfPhdr<L>, segments: &'a ElfSegments) -> Self {
        Self {
            path,
            phdr,
            segments,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    pub fn path(&self) -> &Path {
        self.path
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

/// Context passed to lifecycle handlers when `.init` / `.fini` functions run.
pub struct LifecycleContext<'a> {
    lifecycle: &'a Lifecycle,
    segments: &'a ElfSegments,
}

impl<'a> LifecycleContext<'a> {
    #[inline]
    pub(crate) fn new(lifecycle: &'a Lifecycle, segments: &'a ElfSegments) -> Self {
        Self {
            lifecycle,
            segments,
        }
    }

    /// Returns the lifecycle address table.
    #[inline]
    pub fn lifecycle(&self) -> &Lifecycle {
        self.lifecycle
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> NonNull<u8> {
        self.segments
            .host_ptr(addr)
            .expect("lifecycle function address is not backed by host-accessible mapped memory")
    }

    /// Host pointer of the single lifecycle function, if present.
    #[inline]
    pub fn func_addr(&self) -> Option<NonNull<u8>> {
        self.lifecycle.func_addr().map(|addr| self.host_ptr(addr))
    }

    /// Host pointers from the lifecycle function array.
    #[inline]
    pub fn func_array_addrs(&self) -> impl Iterator<Item = NonNull<u8>> + '_ {
        self.lifecycle
            .func_array_addrs()
            .map(|addr| self.host_ptr(addr))
    }

    /// All lifecycle function host pointers in call order.
    #[inline]
    pub fn func_addrs(&self) -> impl Iterator<Item = NonNull<u8>> + '_ {
        self.lifecycle.func_addrs().map(|addr| self.host_ptr(addr))
    }
}

/// Handler trait for ELF lifecycle callbacks.
///
/// Implementations control how initialization functions such as `.init` / `.init_array`
/// and finalization functions such as `.fini` / `.fini_array` are invoked.
pub trait LifecycleHandler: Send + Sync {
    /// Executes the handler with the provided context.
    fn call(&self, ctx: &LifecycleContext<'_>);
}

impl<F> LifecycleHandler for F
where
    F: Fn(&LifecycleContext<'_>) + Send + Sync,
{
    fn call(&self, ctx: &LifecycleContext<'_>) {
        (self)(ctx)
    }
}

pub(crate) type SharedLifecycleHandler = Arc<dyn LifecycleHandler>;

#[inline]
pub(crate) fn shared_lifecycle_handler<F>(handler: F) -> SharedLifecycleHandler
where
    F: LifecycleHandler + 'static,
{
    Arc::from(Box::new(handler) as Box<dyn LifecycleHandler>)
}
