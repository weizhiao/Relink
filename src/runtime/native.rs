use super::traits::{CodeContext, CodeExecutor};
use crate::{CodeError, Result, memory::VmAddr, relocation::RelocationArch};
use core::ptr::NonNull;

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(always)]
unsafe fn call_native_no_args(ptr: NonNull<u8>) {
    let func: extern "sysv64" fn() = unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    func()
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
#[inline(always)]
unsafe fn call_native_no_args(ptr: NonNull<u8>) {
    let func: extern "C" fn() = unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    func()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    let addr = ptr.as_ptr() as usize;
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let ifunc: extern "sysv64" fn() -> usize = unsafe { core::mem::transmute(addr) };
        Ok(VmAddr::new(ifunc()))
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let ifunc: extern "C" fn() -> usize = unsafe { core::mem::transmute(addr) };
        Ok(VmAddr::new(ifunc()))
    }
}

#[cfg(all(
    target_arch = "arm",
    any(target_os = "linux", target_os = "android"),
    feature = "libc"
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: libc::c_ulong = 16;

    let hwcap = unsafe { libc::getauxval(AT_HWCAP) as usize };
    let ifunc: extern "C" fn(usize) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(hwcap)))
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android"),
    feature = "libc"
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: libc::c_ulong = 16;
    const AT_HWCAP2: libc::c_ulong = 26;
    const AT_HWCAP3: libc::c_ulong = 29;
    const AT_HWCAP4: libc::c_ulong = 30;
    const IFUNC_ARG_HWCAP: usize = 1usize << 62;

    #[repr(C)]
    struct IfuncArg {
        size: usize,
        hwcap: usize,
        hwcap2: usize,
        hwcap3: usize,
        hwcap4: usize,
    }

    let hwcap = unsafe { libc::getauxval(AT_HWCAP) as usize };
    let arg = IfuncArg {
        size: core::mem::size_of::<IfuncArg>(),
        hwcap,
        hwcap2: unsafe { libc::getauxval(AT_HWCAP2) as usize },
        hwcap3: unsafe { libc::getauxval(AT_HWCAP3) as usize },
        hwcap4: unsafe { libc::getauxval(AT_HWCAP4) as usize },
    };
    let ifunc: extern "C" fn(usize, *const IfuncArg) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(hwcap | IFUNC_ARG_HWCAP, &arg)))
}

#[cfg(all(
    any(target_arch = "riscv32", target_arch = "riscv64"),
    any(target_os = "linux", target_os = "android"),
    feature = "libc"
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: libc::c_ulong = 16;

    unsafe extern "C" {
        fn __riscv_hwprobe();
    }

    let hwcap = unsafe { libc::getauxval(AT_HWCAP) as u64 };
    let hwprobe = __riscv_hwprobe as usize as *mut core::ffi::c_void;
    let ifunc: extern "C" fn(u64, *mut core::ffi::c_void, *mut core::ffi::c_void) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(hwcap, hwprobe, core::ptr::null_mut())))
}

#[cfg(all(
    target_arch = "loongarch64",
    any(target_os = "linux", target_os = "android"),
    feature = "libc"
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: libc::c_ulong = 16;

    #[repr(C)]
    struct IfuncArg {
        size: usize,
        hwcap: usize,
    }

    let arg = IfuncArg {
        size: core::mem::size_of::<IfuncArg>(),
        hwcap: unsafe { libc::getauxval(AT_HWCAP) as usize },
    };
    let ifunc: extern "C" fn(*const IfuncArg) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(&arg)))
}

#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    all(
        target_arch = "arm",
        any(target_os = "linux", target_os = "android"),
        feature = "libc"
    ),
    all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android"),
        feature = "libc"
    ),
    all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        any(target_os = "linux", target_os = "android"),
        feature = "libc"
    ),
    all(
        target_arch = "loongarch64",
        any(target_os = "linux", target_os = "android"),
        feature = "libc"
    ),
)))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    let _ = ptr;
    Err(CodeError::NativeUnsupported.into())
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

    #[inline]
    fn call_no_args<Arch: RelocationArch>(
        &self,
        ctx: CodeContext<'_, Arch>,
        addr: VmAddr,
    ) -> Result<()> {
        Self::ensure_supported::<Arch>()?;
        let ptr = ctx.host_ptr(addr)?;
        unsafe { call_native_no_args(ptr) };
        Ok(())
    }
}

impl<Arch: RelocationArch> CodeExecutor<Arch> for NativeCodeExecutor {
    #[inline]
    fn call_init(&self, ctx: CodeContext<'_, Arch>, init: VmAddr) -> Result<()> {
        self.call_no_args(ctx, init)
    }

    #[inline]
    fn call_fini(&self, ctx: CodeContext<'_, Arch>, fini: VmAddr) -> Result<()> {
        self.call_no_args(ctx, fini)
    }

    #[inline]
    fn resolve_ifunc(&self, ctx: CodeContext<'_, Arch>, resolver: VmAddr) -> Result<VmAddr> {
        Self::ensure_supported::<Arch>()?;
        let ptr = ctx.host_ptr(resolver)?;
        debug_assert!(Arch::SUPPORTS_NATIVE_RUNTIME);
        unsafe { resolve_native_ifunc(ptr) }
    }
}
