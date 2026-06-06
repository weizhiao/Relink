use super::{HostRegion, ImageMemory, RegionAccess, VmAddr};
use crate::{
    CodeError, MmapError, Result,
    arch::NativeArch,
    relocation::{RelocationArch, resolve_ifunc},
};
use core::marker::PhantomData;

/// Runtime context for executing code addresses owned by one mapped image.
pub struct CodeContext<'a, Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion> {
    name: &'a str,
    memory: &'a dyn ImageMemory,
    _marker: PhantomData<fn() -> (Arch, R)>,
}

impl<Arch: RelocationArch, R: RegionAccess> Clone for CodeContext<'_, Arch, R> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<Arch: RelocationArch, R: RegionAccess> Copy for CodeContext<'_, Arch, R> {}

impl<'a, Arch: RelocationArch, R: RegionAccess> CodeContext<'a, Arch, R> {
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
pub trait CodeExecutor<Arch: RelocationArch = NativeArch, R: RegionAccess = HostRegion>:
    Send + Sync + 'static
{
    /// Executes a lifecycle-style function with no arguments and no return value.
    fn call_void(&self, ctx: CodeContext<'_, Arch, R>, addr: VmAddr) -> Result<()>;

    /// Executes an IFUNC resolver and returns the resolved implementation address.
    fn resolve_ifunc(&self, _ctx: CodeContext<'_, Arch, R>, _resolver: VmAddr) -> Result<VmAddr> {
        Err(CodeError::NativeUnsupported.into())
    }
}

/// Code executor for images mapped into the current process.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeCodeExecutor;

impl NativeCodeExecutor {
    #[inline]
    fn ensure_supported<Arch: RelocationArch>() -> Result<()> {
        if Arch::SUPPORTS_NATIVE_RUNTIME {
            Ok(())
        } else {
            Err(CodeError::NativeUnsupported.into())
        }
    }
}

impl<Arch: RelocationArch, R: RegionAccess> CodeExecutor<Arch, R> for NativeCodeExecutor {
    #[inline]
    fn call_void(&self, ctx: CodeContext<'_, Arch, R>, addr: VmAddr) -> Result<()> {
        Self::ensure_supported::<Arch>()?;
        let ptr = ctx.host_ptr(addr)?.as_ptr() as usize;
        #[cfg(not(windows))]
        unsafe {
            core::mem::transmute::<usize, extern "C" fn()>(ptr)()
        };
        #[cfg(windows)]
        unsafe {
            core::mem::transmute::<usize, extern "sysv64" fn()>(ptr)()
        };
        Ok(())
    }

    #[inline]
    fn resolve_ifunc(&self, ctx: CodeContext<'_, Arch, R>, resolver: VmAddr) -> Result<VmAddr> {
        Self::ensure_supported::<Arch>()?;
        let ptr = ctx.host_ptr(resolver)?;
        Ok(unsafe { resolve_ifunc(ptr) })
    }
}
