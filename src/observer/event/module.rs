use crate::{
    Result,
    arch::NativeArch,
    image::{CoreInner, ElfCore},
    input::Path,
    os::{HostRegion, RegionAccess, VmAddr},
    relocation::RelocationArch,
    segment::ElfSegments,
    sync::Arc,
};
use alloc::boxed::Box;

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
    core: &'a CoreInner<D, Arch, R>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess> ModuleUnloadEvent<'a, D, Arch, R> {
    #[inline]
    pub(crate) const fn new(core: &'a CoreInner<D, Arch, R>) -> Self {
        Self { core }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.core.path
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.core.name()
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.core.segments.base()
    }

    /// Returns the mapped segments that are still available during unload.
    #[inline]
    pub const fn segments(&self) -> &'a ElfSegments<R> {
        &self.core.segments
    }

    /// Returns the module user data.
    #[inline]
    pub const fn user_data(&self) -> &'a D {
        &self.core.user_data
    }
}
