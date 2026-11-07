use super::{
    context::LinkContext,
    run::LinkerRun,
    scan::LinkPipeline,
    storage::{ModuleId, ModuleLease},
    unload::UnloadGroup,
};
use crate::{
    Loader, Relocator, Result,
    arch::NativeArch,
    const_builder::NoDrop,
    os::Mmap,
    relocation::{LookupOrder, RelocationArch},
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData, mem::MaybeUninit, ptr};

/// Result of a fully initialized linker load operation.
///
/// `modules` contains the newly loaded modules' [`ModuleId`](crate::linker::ModuleId)
/// values in load order. The result owns one lease for the root module; release
/// the result when that direct use ends. Dropping `LoadResult` alone does not
/// release that acquisition from its [`LinkContext`].
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

    /// Splits this result into its root lease and newly loaded module ids.
    #[inline]
    pub fn into_parts(self) -> (ModuleLease, Box<[ModuleId]>) {
        (self.lease, self.modules)
    }

    /// Releases the root acquisition represented by this load.
    #[inline]
    pub fn release<Meta, Arch, Tls>(
        self,
        context: &mut LinkContext<Meta, Arch, Tls>,
    ) -> Result<UnloadGroup<Meta, Arch>>
    where
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
    {
        context.release(self.lease)
    }
}

/// Loads and relocates an ELF image and its `DT_NEEDED` dependencies.
///
/// Combines a [`Loader`](crate::Loader), dependency resolver, and
/// [`Relocator`](crate::Relocator). Loaded modules belong to the supplied
/// [`LinkContext`](crate::LinkContext), so the linker can be reused across contexts.
///
/// Immediate relocation searches the full load group. Lazy PLT lookup searches
/// the requesting module's dependency closure and the context's global scope.
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
///     let mut resolver = SearchPathResolver::new();
///     resolver.push_fixed_dir("plugins");
///
///     let linker = Linker::new().with_resolver(resolver);
///     let mut context = LinkContext::for_process();
///
///     let mut run = linker.run();
///     let loaded = run.load(&mut context, PathBuf::from("libplugin.so"))?;
///     let entry = unsafe {
///         context
///             .module(loaded.root())?
///             .get::<extern "C" fn()>("plugin_entry")?
///             .expect("symbol `plugin_entry` not found")
///     };
///     entry();
///     drop(loaded.release(&mut context)?);
///     Ok(())
/// }
/// ```
pub struct Linker<Arch: RelocationArch = NativeArch, L = Loader<(), Arch>, R = (), RelocBinder = ()>
{
    pub(super) loader: L,
    pub(super) resolver: R,
    pub(super) relocator: Relocator<RelocBinder>,
    marker: PhantomData<Arch>,
}

impl<Arch, L, R, RelocBinder> Clone for Linker<Arch, L, R, RelocBinder>
where
    Arch: RelocationArch,
    L: Clone,
    R: Clone,
    Relocator<RelocBinder>: Clone,
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

    /// Selects the target architecture before attaching a loader.
    ///
    /// The loader and [`crate::LinkContext`] must use the same architecture.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub const fn with_arch<NewArch>(self) -> Linker<NewArch, Loader<(), NewArch>, (), ()>
    where
        NewArch: RelocationArch,
    {
        Linker {
            loader: self.loader.with_arch::<NewArch>(),
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

impl<L, R, RelocBinder, Arch> Linker<Arch, L, R, RelocBinder>
where
    Arch: RelocationArch,
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
    pub const fn with_resolver<NewR>(self, resolver: NewR) -> Linker<Arch, L, NewR, RelocBinder>
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
    pub const fn with_relocator<NewRelocBinder>(
        self,
        relocator: Relocator<NewRelocBinder>,
    ) -> Linker<Arch, L, R, NewRelocBinder>
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
    ) -> Linker<Arch, L, R, NewRelocBinder> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            relocator: configure(self.relocator).defer_init(),
            marker: PhantomData,
        }
    }

    /// Starts a linker run with fresh scratch storage.
    #[inline]
    pub fn run<'pipe, Tls: TlsResolver<Arch>>(
        &self,
    ) -> LinkerRun<'_, 'pipe, Arch, L, R, RelocBinder, Tls, ()> {
        LinkerRun {
            linker: self,
            pipeline: LinkPipeline::new(),
            observer: (),
            caller: None,
            lookup_order: LookupOrder::GlobalFirst,
            scratch_order: Vec::new(),
        }
    }
}

impl<D, Arch, M, R, RelocBinder> Linker<Arch, Loader<D, Arch, M>, R, RelocBinder>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Sets the loader template used to load root modules and dependencies.
    #[allow(clippy::type_complexity)]
    pub const fn with_loader<NewD, NewM>(
        self,
        loader: Loader<NewD, Arch, NewM>,
    ) -> Linker<Arch, Loader<NewD, Arch, NewM>, R, RelocBinder>
    where
        Loader<D, Arch, M>: Copy,
        NewD: Send + Sync + 'static,
        NewM: Mmap,
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
    #[allow(clippy::type_complexity)]
    pub fn map_loader<NewD, NewM>(
        self,
        configure: impl FnOnce(Loader<D, Arch, M>) -> Loader<NewD, Arch, NewM>,
    ) -> Linker<Arch, Loader<NewD, Arch, NewM>, R, RelocBinder>
    where
        NewD: Send + Sync + 'static,
        NewM: Mmap,
    {
        Linker {
            loader: configure(self.loader),
            resolver: self.resolver,
            relocator: self.relocator,
            marker: PhantomData,
        }
    }
}
