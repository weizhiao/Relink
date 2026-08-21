use super::{
    context::LinkContext,
    run::LinkerRun,
    scan::LinkPipeline,
    storage::{ModuleId, ModuleLease},
    unload::UnloadGroup,
};
use crate::{
    Loader, Relocator, Result, arch::NativeArch, const_builder::NoDrop, os::Mmap,
    relocation::RelocationArch, runtime::CodeExecutor, tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData, mem::MaybeUninit, ptr};

/// Result of a fully initialized linker load operation.
///
/// `modules` contains the newly loaded modules' [`ModuleId`](crate::linker::ModuleId)
/// values in load order. The result owns one lease for the root module; release
/// the result when that direct use ends.
#[must_use = "a loaded module lease must eventually be released"]
pub struct LoadResult {
    lease: ModuleLease,
    modules: Box<[ModuleId]>,
}

impl fmt::Debug for LoadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadResult")
            .field("root_id", &self.lease.id())
            .field("modules", &self.modules)
            .finish()
    }
}

impl LoadResult {
    #[inline]
    pub(crate) fn new(lease: ModuleLease, modules: Box<[ModuleId]>) -> Self {
        Self { lease, modules }
    }

    /// Returns the loaded root module id.
    #[inline]
    pub const fn root(&self) -> ModuleId {
        self.lease.id()
    }

    /// Returns module ids produced by this load operation in load order.
    #[inline]
    pub fn modules(&self) -> &[ModuleId] {
        &self.modules
    }

    /// Releases the root acquisition represented by this load.
    #[inline]
    pub fn release<Meta, Arch, Tls>(
        self,
        context: &mut LinkContext<Meta, Arch, Tls>,
    ) -> Result<UnloadGroup<Meta, Arch, Tls>>
    where
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
    {
        context.release(self.lease)
    }
}

/// Reusable front-end for dependency discovery, loading, and relocation.
///
/// `Linker` combines a [`Loader`](crate::Loader), dependency resolver, and
/// [`Relocator`](crate::Relocator).
/// It is the high-level path for loading a root image plus its `DT_NEEDED`
/// dependency graph into a [`LinkContext`](crate::LinkContext).
///
/// The linker is configuration; committed modules live in the context passed to
/// [`Linker::load`]. This lets the same linker value be reused with independent
/// contexts while keeping each context's module ids and dependency graph isolated.
///
/// # Example
///
/// ```rust,no_run
/// use elf_loader::{
///     LinkContext, Linker, Result,
///     input::PathBuf,
///     linker::SearchPathResolver,
///     runtime::DomainId,
/// };
///
/// fn main() -> Result<()> {
///     let mut resolver = SearchPathResolver::new();
///     resolver.push_fixed_dir("plugins");
///
///     let linker = Linker::new().resolver(resolver);
///     let mut context = LinkContext::<()>::new(DomainId::PROCESS);
///
///     let mut run = linker.run();
///     let loaded = run.load(&mut context, PathBuf::from("libplugin.so"))?;
///     let entry = unsafe {
///         context
///             .module(loaded.root())?
///             .get::<extern "C" fn()>("plugin_entry")
///             .expect("symbol `plugin_entry` not found")
///     };
///     entry();
///     Ok(())
/// }
/// ```
pub struct Linker<
    Arch: RelocationArch = NativeArch,
    L = Loader<(), (), Arch>,
    R = (),
    RelocBinder = (),
    Tls: TlsResolver<Arch> = (),
> {
    pub(super) loader: L,
    pub(super) resolver: R,
    pub(super) relocator: Relocator<RelocBinder>,
    marker: PhantomData<(Arch, Tls)>,
}

impl<Arch, L, R, RelocBinder, Tls> Clone for Linker<Arch, L, R, RelocBinder, Tls>
where
    Arch: RelocationArch,
    L: Clone,
    R: Clone,
    Relocator<RelocBinder>: Clone,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            loader: self.loader.clone(),
            resolver: self.resolver.clone(),
            relocator: self.relocator.clone(),
            marker: PhantomData,
        }
    }
}

struct LinkerFields<L, R, RelocBinder> {
    loader: NoDrop<L>,
    resolver: NoDrop<R>,
    relocator: NoDrop<Relocator<RelocBinder>>,
}

impl Linker {
    /// Creates a linker using the default loader and native target architecture.
    #[inline]
    pub const fn new() -> Self {
        Self {
            loader: Loader::new(),
            resolver: (),
            relocator: Relocator::new().defer_init(),
            marker: PhantomData,
        }
    }

    /// Switch the linker's relocation domain before a loader is attached.
    ///
    /// This mirrors [`Loader::for_arch`] for the dependency-linking front-end:
    /// all modules committed through the resulting [`crate::LinkContext`] use
    /// `NewArch`.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub const fn for_arch<NewArch>(self) -> Linker<NewArch, Loader<(), (), NewArch>, (), ()>
    where
        NewArch: RelocationArch,
    {
        Linker {
            loader: self.loader.for_arch::<NewArch>(),
            resolver: (),
            relocator: self.relocator,
            marker: PhantomData,
        }
    }
}

impl Default for Linker {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<L, R, RelocBinder, Arch, Tls> Linker<Arch, L, R, RelocBinder, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    const fn into_fields(self) -> LinkerFields<L, R, RelocBinder> {
        let this = MaybeUninit::new(self);
        let this = this.as_ptr();

        // SAFETY: `this` points at the fully initialized `self` stored inside
        // `MaybeUninit`, so every field read below is initialized and aligned.
        // The original `Linker` is intentionally not dropped; builder methods
        // that replace a field require that old field to be `Copy`.
        unsafe {
            LinkerFields {
                loader: NoDrop::read(ptr::addr_of!((*this).loader)),
                resolver: NoDrop::read(ptr::addr_of!((*this).resolver)),
                relocator: NoDrop::read(ptr::addr_of!((*this).relocator)),
            }
        }
    }

    /// Sets the key resolver used to resolve root keys and dependencies.
    pub const fn resolver<NewR>(self, resolver: NewR) -> Linker<Arch, L, NewR, RelocBinder, Tls>
    where
        R: Copy,
    {
        let LinkerFields {
            loader, relocator, ..
        } = self.into_fields();

        Linker {
            loader: loader.into_inner(),
            resolver,
            relocator: relocator.into_inner(),
            marker: PhantomData,
        }
    }

    /// Sets the relocator template used for loaded modules.
    ///
    /// Dynamic initialization remains deferred until after the module group is committed.
    pub const fn relocator<NewRelocBinder>(
        self,
        relocator: Relocator<NewRelocBinder>,
    ) -> Linker<Arch, L, R, NewRelocBinder, Tls>
    where
        Relocator<RelocBinder>: Copy,
    {
        let LinkerFields {
            loader, resolver, ..
        } = self.into_fields();

        Linker {
            loader: loader.into_inner(),
            resolver: resolver.into_inner(),
            relocator: relocator.defer_init(),
            marker: PhantomData,
        }
    }

    /// Reconfigures the relocator template used for loaded modules.
    ///
    /// Dynamic initialization remains deferred until after the module group is committed.
    pub fn map_relocator<NewRelocBinder>(
        self,
        configure: impl FnOnce(Relocator<RelocBinder>) -> Relocator<NewRelocBinder>,
    ) -> Linker<Arch, L, R, NewRelocBinder, Tls> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            relocator: configure(self.relocator).defer_init(),
            marker: PhantomData,
        }
    }

    /// Starts a linker run with fresh scratch storage.
    #[inline]
    pub fn run<'pipe>(&self) -> LinkerRun<'_, 'pipe, Arch, L, R, RelocBinder, Tls, ()> {
        LinkerRun {
            linker: self,
            pipeline: LinkPipeline::new(),
            observer: (),
            scratch_order: Vec::new(),
        }
    }
}

impl<D: Send + Sync + 'static, Tls, Arch, M, Exec, R>
    Linker<Arch, Loader<D, Tls, Arch, M, Exec>, R, (), Tls>
where
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Sets the loader template used to load root modules and dependencies.
    ///
    /// This must run before configuring the relocator because changing the
    /// loader can also change the TLS resolver type.
    #[allow(clippy::type_complexity)]
    pub const fn loader<NewD, NewTls, NewM, NewExec>(
        self,
        loader: Loader<NewD, NewTls, Arch, NewM, NewExec>,
    ) -> Linker<Arch, Loader<NewD, NewTls, Arch, NewM, NewExec>, R, (), NewTls>
    where
        Loader<D, Tls, Arch, M, Exec>: Copy,
        NewD: Send + Sync + 'static,
        NewTls: TlsResolver<Arch>,
        NewM: Mmap,
        NewExec: CodeExecutor<Arch> + Clone,
    {
        let LinkerFields {
            relocator,
            resolver,
            ..
        } = self.into_fields();

        Linker {
            loader,
            resolver: resolver.into_inner(),
            relocator: relocator.into_inner(),
            marker: PhantomData,
        }
    }

    /// Reconfigures the underlying loader.
    ///
    /// This must run before configuring the relocator because changing the
    /// loader can also change the TLS resolver type.
    #[allow(clippy::type_complexity)]
    pub fn map_loader<NewD, NewTls, NewM, NewExec>(
        self,
        configure: impl FnOnce(
            Loader<D, Tls, Arch, M, Exec>,
        ) -> Loader<NewD, NewTls, Arch, NewM, NewExec>,
    ) -> Linker<Arch, Loader<NewD, NewTls, Arch, NewM, NewExec>, R, (), NewTls>
    where
        NewD: Send + Sync + 'static,
        NewTls: TlsResolver<Arch>,
        NewM: Mmap,
        NewExec: CodeExecutor<Arch> + Clone,
    {
        Linker {
            loader: configure(self.loader),
            resolver: self.resolver,
            relocator: self.relocator,
            marker: PhantomData,
        }
    }
}
