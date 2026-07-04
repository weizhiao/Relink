use crate::{
    MmapError, Result,
    arch::NativeArch,
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    sync::Arc,
};
use core::marker::PhantomData;

/// Runtime context for executing code addresses owned by one mapped image.
pub struct CodeContext<'a, Arch: RelocationArch = NativeArch> {
    name: &'a str,
    memory: &'a dyn ImageMemory,
    _marker: PhantomData<fn() -> Arch>,
}

impl<Arch: RelocationArch> Clone for CodeContext<'_, Arch> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<Arch: RelocationArch> Copy for CodeContext<'_, Arch> {}

impl<'a, Arch: RelocationArch> CodeContext<'a, Arch> {
    #[inline]
    pub(crate) fn new(name: &'a str, memory: &'a dyn ImageMemory) -> Self {
        Self {
            name,
            memory,
            _marker: PhantomData,
        }
    }

    /// Returns the module identity used for diagnostics.
    #[inline]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the load base used by this image.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.memory.base()
    }

    /// Translates an image VM address into a host-accessible pointer.
    #[inline]
    pub fn host_ptr(&self, addr: VmAddr) -> Result<core::ptr::NonNull<u8>> {
        self.memory
            .host_ptr(addr)
            .ok_or(MmapError::HostPointerUnavailable.into())
    }
}

/// Executes runtime code addresses for a mapped image.
///
/// Native hosts can call through host pointers. Remote process, guest,
/// kernel-module, or bare-metal environments can provide their own executor
/// that interprets VM addresses in their runtime.
pub trait CodeExecutor<Arch: RelocationArch = NativeArch>: Send + Sync + 'static {
    /// Executes an initialization function.
    fn call_init(&self, ctx: CodeContext<'_, Arch>, init: VmAddr) -> Result<()>;

    /// Executes a finalization function.
    fn call_fini(&self, ctx: CodeContext<'_, Arch>, fini: VmAddr) -> Result<()>;

    /// Executes an IFUNC resolver and returns the resolved implementation address.
    fn resolve_ifunc(&self, ctx: CodeContext<'_, Arch>, resolver: VmAddr) -> Result<VmAddr>;
}

impl<Arch, E> CodeExecutor<Arch> for Arc<E>
where
    Arch: RelocationArch,
    E: CodeExecutor<Arch> + ?Sized,
{
    #[inline]
    fn call_init(&self, ctx: CodeContext<'_, Arch>, init: VmAddr) -> Result<()> {
        (**self).call_init(ctx, init)
    }

    #[inline]
    fn call_fini(&self, ctx: CodeContext<'_, Arch>, fini: VmAddr) -> Result<()> {
        (**self).call_fini(ctx, fini)
    }

    #[inline]
    fn resolve_ifunc(&self, ctx: CodeContext<'_, Arch>, resolver: VmAddr) -> Result<VmAddr> {
        (**self).resolve_ifunc(ctx, resolver)
    }
}
