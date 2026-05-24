use crate::{
    Result,
    arch::{ArchKind, NativeArch},
    elf::{ElfDyn, ElfDynamicTag, ElfLayout, ElfPhdr, NativeElfLayout},
    image::{ElfCore, RawDynamic},
    input::Path,
    os::{HostRegion, RegionAccess, VmAddr},
    relocation::{RelocValue, RelocationArch},
    segment::ElfSegments,
    sync::Arc,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

/// Root-module resolution event emitted by the linker.
pub struct ResolveRootEvent<'a, K> {
    key: &'a K,
}

impl<'a, K> ResolveRootEvent<'a, K> {
    #[inline]
    pub(crate) const fn new(key: &'a K) -> Self {
        Self { key }
    }

    /// Returns the root key requested by the caller.
    #[inline]
    pub const fn key(&self) -> &'a K {
        self.key
    }
}

/// Dependency-resolution event emitted for one `DT_NEEDED` edge.
pub struct ResolveDependencyEvent<'a, K> {
    owner_key: &'a K,
    owner_name: &'a str,
    owner_path: &'a Path,
    needed: &'a str,
    needed_index: usize,
    rpath: Option<&'a str>,
    runpath: Option<&'a str>,
    interp: Option<&'a str>,
}

impl<'a, K> ResolveDependencyEvent<'a, K> {
    #[inline]
    pub(crate) const fn new(
        owner_key: &'a K,
        owner_name: &'a str,
        owner_path: &'a Path,
        needed: &'a str,
        needed_index: usize,
        rpath: Option<&'a str>,
        runpath: Option<&'a str>,
        interp: Option<&'a str>,
    ) -> Self {
        Self {
            owner_key,
            owner_name,
            owner_path,
            needed,
            needed_index,
            rpath,
            runpath,
            interp,
        }
    }

    /// Returns the key of the module that owns this dependency edge.
    #[inline]
    pub const fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns the owner name used in diagnostics.
    #[inline]
    pub const fn owner_name(&self) -> &'a str {
        self.owner_name
    }

    /// Returns the owner path or caller-provided source identifier.
    #[inline]
    pub const fn owner_path(&self) -> &'a Path {
        self.owner_path
    }

    /// Returns the requested `DT_NEEDED` library name.
    #[inline]
    pub const fn needed(&self) -> &'a str {
        self.needed
    }

    /// Returns the index of this dependency in the owner's `DT_NEEDED` list.
    #[inline]
    pub const fn needed_index(&self) -> usize {
        self.needed_index
    }

    /// Returns the owner's `DT_RPATH`, if present.
    #[inline]
    pub const fn rpath(&self) -> Option<&'a str> {
        self.rpath
    }

    /// Returns the owner's `DT_RUNPATH`, if present.
    #[inline]
    pub const fn runpath(&self) -> Option<&'a str> {
        self.runpath
    }

    /// Returns the owner's `PT_INTERP` path, if present.
    #[inline]
    pub const fn interp(&self) -> Option<&'a str> {
        self.interp
    }
}

/// Program-header event emitted while an ELF image is being loaded.
pub struct ProgramHeaderEvent<'a, L: ElfLayout = NativeElfLayout> {
    path: &'a Path,
    phdr: &'a ElfPhdr<L>,
    segments: &'a ElfSegments,
}

impl<'a, L: ElfLayout> ProgramHeaderEvent<'a, L> {
    #[inline]
    pub(crate) const fn new(
        path: &'a Path,
        phdr: &'a ElfPhdr<L>,
        segments: &'a ElfSegments,
    ) -> Self {
        Self {
            path,
            phdr,
            segments,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub const fn path(&self) -> &Path {
        self.path
    }

    /// Returns the program header being processed.
    #[inline]
    pub const fn phdr(&self) -> &ElfPhdr<L> {
        self.phdr
    }

    /// Returns the ELF segments built for this image.
    #[inline]
    pub const fn segments(&self) -> &ElfSegments {
        self.segments
    }
}

/// A mapped but unrelocated dynamic image observed during a link operation.
pub struct StagedDynamic<'a, K, D: 'static, Arch: RelocationArch = NativeArch> {
    key: &'a K,
    raw: &'a RawDynamic<D, Arch>,
}

impl<'a, K, D: 'static, Arch> StagedDynamic<'a, K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) const fn new(key: &'a K, raw: &'a RawDynamic<D, Arch>) -> Self {
        Self { key, raw }
    }

    /// Returns the key of the staged module.
    #[inline]
    pub const fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the architecture kind of the staged module.
    #[inline]
    pub const fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    /// Returns the mapped byte length of the staged module.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.raw.mapped_len()
    }

    /// Returns the unrelocated dynamic image.
    #[inline]
    pub const fn raw(&self) -> &'a RawDynamic<D, Arch> {
        self.raw
    }
}

/// Runtime linker state change notification.
///
/// These states intentionally mirror the shape of the classic `r_debug.r_state`
/// values without requiring Relink to own an `r_debug` or `link_map` instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkActivity {
    /// The loaded module set is being extended.
    Add,
    /// The loaded module set is being reduced.
    Delete,
    /// The loaded module set is stable.
    Consistent,
}

/// A mutable `DT_DEBUG` dynamic entry discovered in an image.
///
/// The observer decides whether and how to patch it. This keeps debugger-facing
/// state such as `r_debug` and `link_map` owned by the embedding runtime.
pub struct DtDebugEntry<'a, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    addr: VmAddr,
    segments: &'a ElfSegments<R>,
    _marker: PhantomData<fn() -> Arch>,
}

impl<'a, Arch: RelocationArch, R: RegionAccess> DtDebugEntry<'a, Arch, R> {
    #[inline]
    pub(crate) const fn new(addr: VmAddr, segments: &'a ElfSegments<R>) -> Self {
        Self {
            addr,
            segments,
            _marker: PhantomData,
        }
    }

    /// Returns the runtime address of the `DT_DEBUG` dynamic entry.
    #[inline]
    pub const fn addr(&self) -> VmAddr {
        self.addr
    }

    /// Writes the runtime address of an externally owned `r_debug` object.
    #[inline]
    pub fn write_r_debug_addr(&self, addr: VmAddr) -> Result<()> {
        let entry = ElfDyn::<Arch::Layout>::new(ElfDynamicTag::DEBUG, addr.get());
        unsafe { self.segments.write_value(self.addr, RelocValue::new(entry)) }
    }
}

/// Event emitted after a dynamic image has been relocated.
pub struct ModuleRelocatedEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    core: &'a ElfCore<D, Arch, R>,
    dynamic_addr: VmAddr,
    unload_hook: Option<SharedModuleUnloadHook<D, Arch, R>>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> ModuleRelocatedEvent<'a, D, Arch, R> {
    #[inline]
    pub(crate) const fn new(core: &'a ElfCore<D, Arch, R>, dynamic_addr: VmAddr) -> Self {
        Self {
            core,
            dynamic_addr,
            unload_hook: None,
        }
    }

    /// Returns the image core associated with this event.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R> {
        self.core
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.core.path()
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.core.base()
    }

    /// Returns the runtime address of the first dynamic entry.
    #[inline]
    pub const fn dynamic_addr(&self) -> VmAddr {
        self.dynamic_addr
    }

    /// Installs a callback that will run when this module is dropped.
    ///
    /// The original relocation observer is usually gone by then, so unload
    /// handling is represented as a per-module hook captured during load.
    #[inline]
    pub fn set_unload_hook<F>(&mut self, hook: F)
    where
        F: for<'unload> Fn(ModuleUnloadEvent<'unload, D, Arch, R>) -> Result<()>
            + Send
            + Sync
            + 'static,
    {
        self.unload_hook = Some(Arc::from(Box::new(hook)
            as Box<
                dyn for<'unload> Fn(ModuleUnloadEvent<'unload, D, Arch, R>) -> Result<()>
                    + Send
                    + Sync,
            >));
    }

    #[inline]
    pub(crate) fn into_unload_hook(self) -> Option<SharedModuleUnloadHook<D, Arch, R>> {
        self.unload_hook
    }
}

pub(crate) type SharedModuleUnloadHook<D, Arch = NativeArch, R = HostRegion> =
    Arc<dyn for<'a> Fn(ModuleUnloadEvent<'a, D, Arch, R>) -> Result<()> + Send + Sync>;

/// Module-level event emitted when a loaded image is being dropped.
pub struct ModuleUnloadEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    path: &'a Path,
    name: &'a str,
    base: VmAddr,
    segments: &'a ElfSegments<R>,
    user_data: &'a D,
    _marker: PhantomData<fn() -> Arch>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> ModuleUnloadEvent<'a, D, Arch, R> {
    #[inline]
    pub(crate) const fn new(
        path: &'a Path,
        name: &'a str,
        base: VmAddr,
        segments: &'a ElfSegments<R>,
        user_data: &'a D,
    ) -> Self {
        Self {
            path,
            name,
            base,
            segments,
            user_data,
            _marker: PhantomData,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub const fn path(&self) -> &'a Path {
        self.path
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the load base used by this image.
    #[inline]
    pub const fn base(&self) -> VmAddr {
        self.base
    }

    /// Returns the mapped segments that are still available during unload.
    #[inline]
    pub const fn segments(&self) -> &'a ElfSegments<R> {
        self.segments
    }

    /// Returns the module user data.
    #[inline]
    pub const fn user_data(&self) -> &'a D {
        self.user_data
    }
}
