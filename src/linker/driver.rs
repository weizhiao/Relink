use super::{
    request::DefaultRelocationPlanner, run::LinkerRun, scan::LinkPipeline,
    storage::ModuleId as CommittedModuleId,
};
use crate::{
    Loader,
    const_builder::NoDrop,
    image::LoadedCore,
    memory::RegionAccess,
    os::Mmap,
    relocation::{RelocationArch, Relocator},
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData, mem::MaybeUninit, ops::Deref, ptr};

/// Result of a successful linker load operation.
///
/// `committed` contains the newly committed modules' [`ModuleId`](crate::linker::ModuleId)
/// values in load order.
pub struct LoadResult<
    D: 'static,
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = crate::memory::HostRegion,
    Tls: TlsResolver<Arch> = (),
> {
    root_id: Option<CommittedModuleId>,
    root: LoadedCore<D, Arch, R, Tls>,
    committed: Box<[CommittedModuleId]>,
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
        root_id: Option<CommittedModuleId>,
        root: LoadedCore<D, Arch, R, Tls>,
        committed: Box<[CommittedModuleId]>,
    ) -> Self {
        Self {
            root_id,
            root,
            committed,
        }
    }

    /// Returns the committed module id for the loaded root, if the root belongs
    /// to this link context.
    #[inline]
    pub fn root_id(&self) -> Option<CommittedModuleId> {
        self.root_id
    }

    /// Returns the loaded root module.
    #[inline]
    pub fn root(&self) -> &LoadedCore<D, Arch, R, Tls> {
        &self.root
    }

    /// Returns module ids committed by this load operation in load order.
    #[inline]
    pub fn committed(&self) -> &[CommittedModuleId] {
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

/// Configurable front-end for runtime dependency discovery and relocation.
///
/// `Linker` stores one relocation domain: all modules committed through one
/// context use the same [`RelocationArch`].
#[doc(hidden)]
pub struct Stage0;

#[doc(hidden)]
pub struct Stage1;

#[doc(hidden)]
pub trait AdvanceStage {
    type Next;
}

impl AdvanceStage for Stage0 {
    type Next = Stage1;
}

impl AdvanceStage for Stage1 {
    type Next = Stage1;
}

pub struct Linker<
    'a,
    K: Clone + Ord,
    Arch: RelocationArch = crate::arch::NativeArch,
    L = Loader<(), (), Arch>,
    R = (),
    PreH = (),
    PostH = (),
    RelocBinder = (),
    P = DefaultRelocationPlanner,
    V = (),
    Tls: TlsResolver<Arch> = (),
    Stage = Stage0,
> {
    loader: L,
    resolver: R,
    relocator: Relocator<PreH, PostH, RelocBinder>,
    planner: P,
    visible_modules: V,
    stage: PhantomData<(&'a (), K, Arch, Tls, Stage)>,
}

struct LinkerFields<
    'a,
    K: Clone + Ord,
    Arch: RelocationArch,
    L,
    R,
    PreH,
    PostH,
    RelocBinder,
    P,
    V,
    Tls: TlsResolver<Arch>,
    Stage,
> {
    loader: NoDrop<L>,
    resolver: NoDrop<R>,
    relocator: NoDrop<Relocator<PreH, PostH, RelocBinder>>,
    planner: NoDrop<P>,
    visible_modules: NoDrop<V>,
    stage: PhantomData<(&'a (), K, Arch, Tls, Stage)>,
}

impl<'a, K> Linker<'a, K>
where
    K: Clone + Ord,
{
    /// Creates a linker using the default loader and native target architecture.
    #[inline]
    pub const fn new() -> Self {
        Self {
            loader: Loader::new(),
            resolver: (),
            relocator: Relocator::new(),
            planner: DefaultRelocationPlanner,
            visible_modules: (),
            stage: PhantomData,
        }
    }

    /// Creates a linker from preconfigured loader and relocator templates.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub const fn from_parts<D, Tls, Arch, M, Exec, PreH, PostH, RelocBinder>(
        loader: Loader<D, Tls, Arch, M, Exec>,
        relocator: Relocator<PreH, PostH, RelocBinder>,
    ) -> Linker<
        'a,
        K,
        Arch,
        Loader<D, Tls, Arch, M, Exec>,
        (),
        PreH,
        PostH,
        RelocBinder,
        DefaultRelocationPlanner,
        (),
        Tls,
        Stage0,
    >
    where
        D: 'static,
        Tls: TlsResolver<Arch>,
        Arch: RelocationArch,
        M: Mmap,
        Exec: CodeExecutor<Arch> + Clone,
    {
        Linker {
            loader,
            resolver: (),
            relocator,
            planner: DefaultRelocationPlanner,
            visible_modules: (),
            stage: PhantomData,
        }
    }

    /// Switch the linker's relocation domain before a loader is attached.
    ///
    /// This mirrors [`Loader::for_arch`] for the dependency-linking front-end:
    /// all modules committed through the resulting [`LinkContext`] use
    /// `NewArch`.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub const fn for_arch<NewArch>(
        self,
    ) -> Linker<'a, K, NewArch, Loader<(), (), NewArch>, (), (), (), (), DefaultRelocationPlanner, ()>
    where
        NewArch: RelocationArch,
    {
        Linker {
            loader: self.loader.for_arch::<NewArch>(),
            resolver: (),
            relocator: self.relocator,
            planner: DefaultRelocationPlanner,
            visible_modules: (),
            stage: PhantomData,
        }
    }
}

impl<'a, K> Default for Linker<'a, K>
where
    K: Clone + Ord,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K, L, R, PreH, PostH, RelocBinder, P, V, Arch, Tls, Stage>
    Linker<'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, Stage>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    const fn into_fields(
        self,
    ) -> LinkerFields<'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, Stage> {
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
                planner: NoDrop::read(ptr::addr_of!((*this).planner)),
                visible_modules: NoDrop::read(ptr::addr_of!((*this).visible_modules)),
                stage: ptr::read(ptr::addr_of!((*this).stage)),
            }
        }
    }

    /// Sets the key resolver used to resolve root keys and dependencies.
    pub const fn resolver<NewR>(
        self,
        resolver: NewR,
    ) -> Linker<'a, K, Arch, L, NewR, PreH, PostH, RelocBinder, P, V, Tls, Stage>
    where
        R: Copy,
    {
        let LinkerFields {
            loader,
            relocator,
            planner,
            visible_modules,
            stage,
            ..
        } = self.into_fields();

        Linker {
            loader: loader.into_inner(),
            resolver,
            relocator: relocator.into_inner(),
            planner: planner.into_inner(),
            visible_modules: visible_modules.into_inner(),
            stage,
        }
    }

    /// Sets the relocation planner used after dependency discovery.
    pub const fn planner<NewP>(
        self,
        planner: NewP,
    ) -> Linker<'a, K, Arch, L, R, PreH, PostH, RelocBinder, NewP, V, Tls, Stage>
    where
        P: Copy,
    {
        let LinkerFields {
            loader,
            resolver,
            relocator,
            visible_modules,
            stage,
            ..
        } = self.into_fields();

        Linker {
            loader: loader.into_inner(),
            resolver: resolver.into_inner(),
            relocator: relocator.into_inner(),
            planner,
            visible_modules: visible_modules.into_inner(),
            stage,
        }
    }

    /// Sets additional modules that are visible for reuse or lookup.
    pub const fn visible_modules<NewV>(
        self,
        visible_modules: NewV,
    ) -> Linker<'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, NewV, Tls, Stage>
    where
        V: Copy,
    {
        let LinkerFields {
            loader,
            resolver,
            relocator,
            planner,
            stage,
            ..
        } = self.into_fields();

        Linker {
            loader: loader.into_inner(),
            resolver: resolver.into_inner(),
            relocator: relocator.into_inner(),
            planner: planner.into_inner(),
            visible_modules,
            stage,
        }
    }

    /// Starts a linker run with fresh scratch storage.
    #[inline]
    pub fn run(&self) -> LinkerRun<'_, 'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, ()> {
        LinkerRun {
            loader: &self.loader,
            resolver: &self.resolver,
            pipeline: LinkPipeline::new(),
            relocator: &self.relocator,
            planner: &self.planner,
            visible_modules: &self.visible_modules,
            observer: (),
            scratch_relocation_order: Vec::new(),
        }
    }
}

impl<'a, K, L, R, PreH, PostH, RelocBinder, P, V, Arch, Tls, Stage>
    Linker<'a, K, Arch, L, R, PreH, PostH, RelocBinder, P, V, Tls, Stage>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    Stage: AdvanceStage,
{
    /// Reconfigures the relocator template used for loaded modules.
    pub fn map_relocator<NewPreH, NewPostH, NewRelocBinder>(
        self,
        configure: impl FnOnce(
            Relocator<PreH, PostH, RelocBinder>,
        ) -> Relocator<NewPreH, NewPostH, NewRelocBinder>,
    ) -> Linker<'a, K, Arch, L, R, NewPreH, NewPostH, NewRelocBinder, P, V, Tls, Stage::Next> {
        Linker {
            loader: self.loader,
            resolver: self.resolver,
            relocator: configure(self.relocator),
            planner: self.planner,
            visible_modules: self.visible_modules,
            stage: PhantomData,
        }
    }
}

impl<'a, K, D, Tls, Arch, M, Exec, R, P, V>
    Linker<'a, K, Arch, Loader<D, Tls, Arch, M, Exec>, R, (), (), (), P, V, Tls, Stage0>
where
    K: Clone + Ord,
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
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
    ) -> Linker<
        'a,
        K,
        Arch,
        Loader<NewD, NewTls, Arch, NewM, NewExec>,
        R,
        (),
        (),
        (),
        P,
        V,
        NewTls,
        Stage0,
    >
    where
        NewD: 'static,
        NewTls: TlsResolver<Arch>,
        NewM: Mmap,
        NewExec: CodeExecutor<Arch> + Clone,
    {
        Linker {
            loader: configure(self.loader),
            resolver: self.resolver,
            relocator: Relocator::new(),
            planner: self.planner,
            visible_modules: self.visible_modules,
            stage: PhantomData,
        }
    }
}
