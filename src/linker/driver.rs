use super::{run::LinkerRun, scan::LinkPipeline, storage::ModuleId};
use crate::{
    Loader, Relocator, const_builder::NoDrop, image::LoadedCore, memory::RegionAccess, os::Mmap,
    relocation::RelocationArch, runtime::CodeExecutor, tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData, mem::MaybeUninit, ops::Deref, ptr};

/// Result of a fully initialized linker load operation.
///
/// `committed` contains the newly committed modules' [`ModuleId`](crate::linker::ModuleId)
/// values in load order.
pub struct LoadResult<
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = crate::memory::HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    root_id: ModuleId,
    root: LoadedCore<D, Arch, R, Tls>,
    committed: Box<[ModuleId]>,
}

impl<D: 'static, Arch, R, Tls> fmt::Debug for LoadResult<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadResult")
            .field("root_id", &self.root_id)
            .field("root", &self.root.name())
            .field("committed", &self.committed)
            .finish()
    }
}

impl<D: 'static, Arch, R, Tls> LoadResult<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(
        root_id: ModuleId,
        root: LoadedCore<D, Arch, R, Tls>,
        committed: Box<[ModuleId]>,
    ) -> Self {
        Self {
            root_id,
            root,
            committed,
        }
    }

    /// Returns the committed module id for the loaded root.
    #[inline]
    pub fn root_id(&self) -> ModuleId {
        self.root_id
    }

    /// Returns the loaded root module.
    #[inline]
    pub fn root(&self) -> &LoadedCore<D, Arch, R, Tls> {
        &self.root
    }

    /// Returns module ids committed by this load operation in load order.
    #[inline]
    pub fn committed(&self) -> &[ModuleId] {
        &self.committed
    }

    /// Consumes the result and returns the loaded root module.
    #[inline]
    pub fn into_root(self) -> LoadedCore<D, Arch, R, Tls> {
        self.root
    }
}

impl<D: 'static, Arch, R, Tls> Deref for LoadResult<D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    type Target = LoadedCore<D, Arch, R, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.root
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
/// };
///
/// fn main() -> Result<()> {
///     let mut resolver = SearchPathResolver::<PathBuf>::new();
///     resolver.push_fixed_dir("plugins");
///
///     let linker = Linker::<PathBuf>::new().resolver(resolver);
///     let mut context: LinkContext<PathBuf, ()> = LinkContext::new();
///
///     let mut run = linker.run();
///     let loaded = run.load(&mut context, PathBuf::from("libplugin.so"))?;
///     let entry = unsafe {
///         loaded
///             .get::<extern "C" fn()>("plugin_entry")
///             .expect("symbol `plugin_entry` not found")
///     };
///     entry();
///     Ok(())
/// }
/// ```
pub struct Linker<
    K: Clone + Ord,
    Arch: RelocationArch = crate::arch::NativeArch,
    L = Loader<(), (), Arch>,
    R = (),
    RelocBinder = (),
    Tls: TlsResolver<Arch> = (),
> {
    pub(super) loader: L,
    pub(super) resolver: R,
    pub(super) relocator: Relocator<RelocBinder>,
    marker: PhantomData<(K, Arch, Tls)>,
}

impl<K, Arch, L, R, RelocBinder, Tls> Clone for Linker<K, Arch, L, R, RelocBinder, Tls>
where
    K: Clone + Ord,
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

impl<K> Linker<K>
where
    K: Clone + Ord,
{
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
    pub const fn for_arch<NewArch>(self) -> Linker<K, NewArch, Loader<(), (), NewArch>, (), ()>
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

impl<K> Default for Linker<K>
where
    K: Clone + Ord,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, L, R, RelocBinder, Arch, Tls> Linker<K, Arch, L, R, RelocBinder, Tls>
where
    K: Clone + Ord,
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
    pub const fn resolver<NewR>(self, resolver: NewR) -> Linker<K, Arch, L, NewR, RelocBinder, Tls>
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
    ) -> Linker<K, Arch, L, R, NewRelocBinder, Tls>
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
    ) -> Linker<K, Arch, L, R, NewRelocBinder, Tls> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            relocator: configure(self.relocator).defer_init(),
            marker: PhantomData,
        }
    }

    /// Starts a linker run with fresh scratch storage.
    #[inline]
    pub fn run<'pipe>(&self) -> LinkerRun<'_, 'pipe, K, Arch, L, R, RelocBinder, Tls, ()> {
        LinkerRun {
            linker: self,
            pipeline: LinkPipeline::new(),
            observer: (),
            scratch_relocation_order: Vec::new(),
        }
    }
}

impl<K, D, Tls, Arch, M, Exec, R> Linker<K, Arch, Loader<D, Tls, Arch, M, Exec>, R, (), Tls>
where
    K: Clone + Ord,
    D: 'static,
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
    ) -> Linker<K, Arch, Loader<NewD, NewTls, Arch, NewM, NewExec>, R, (), NewTls>
    where
        Loader<D, Tls, Arch, M, Exec>: Copy,
        NewD: 'static,
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
    ) -> Linker<K, Arch, Loader<NewD, NewTls, Arch, NewM, NewExec>, R, (), NewTls>
    where
        NewD: 'static,
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
