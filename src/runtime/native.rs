use super::traits::{CodeContext, CodeExecutor};
use crate::{CodeError, Result, memory::VmAddr, relocation::RelocationArch, tls::TlsIndex};
use core::ptr::NonNull;

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(always)]
unsafe fn call_native_no_args(ptr: NonNull<u8>) {
    let func: extern "sysv64" fn() = unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    func()
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(always)]
unsafe fn resolve_native_tls(resolver: VmAddr, index: &TlsIndex) -> VmAddr {
    let func: extern "sysv64" fn(*const TlsIndex) -> *mut u8 =
        unsafe { core::mem::transmute(resolver.get()) };
    VmAddr::from_ptr(func(index))
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
#[inline(always)]
unsafe fn resolve_native_tls(resolver: VmAddr, index: &TlsIndex) -> VmAddr {
    let func: extern "C" fn(*const TlsIndex) -> *mut u8 =
        unsafe { core::mem::transmute(resolver.get()) };
    VmAddr::from_ptr(func(index))
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
    any(feature = "libc", feature = "use-syscall")
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: usize = 16;

    let hwcap = crate::os::getauxval(AT_HWCAP);
    let ifunc: extern "C" fn(usize) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(hwcap)))
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android"),
    any(feature = "libc", feature = "use-syscall")
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: usize = 16;
    const AT_HWCAP2: usize = 26;
    const AT_HWCAP3: usize = 29;
    const AT_HWCAP4: usize = 30;
    const IFUNC_ARG_HWCAP: usize = 1usize << 62;

    #[repr(C)]
    struct IfuncArg {
        size: usize,
        hwcap: usize,
        hwcap2: usize,
        hwcap3: usize,
        hwcap4: usize,
    }

    let hwcap = crate::os::getauxval(AT_HWCAP);
    let arg = IfuncArg {
        size: core::mem::size_of::<IfuncArg>(),
        hwcap,
        hwcap2: crate::os::getauxval(AT_HWCAP2),
        hwcap3: crate::os::getauxval(AT_HWCAP3),
        hwcap4: crate::os::getauxval(AT_HWCAP4),
    };
    let ifunc: extern "C" fn(usize, *const IfuncArg) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(hwcap | IFUNC_ARG_HWCAP, &arg)))
}

#[cfg(all(
    any(target_arch = "riscv32", target_arch = "riscv64"),
    any(target_os = "linux", target_os = "android"),
    any(feature = "libc", feature = "use-syscall")
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: usize = 16;

    let hwcap = crate::os::getauxval(AT_HWCAP) as u64;
    let hwprobe = riscv_hwprobe();
    let ifunc: extern "C" fn(u64, *mut core::ffi::c_void, *mut core::ffi::c_void) -> usize =
        unsafe { core::mem::transmute(ptr.as_ptr() as usize) };
    Ok(VmAddr::new(ifunc(hwcap, hwprobe, core::ptr::null_mut())))
}

#[cfg(all(
    any(target_arch = "riscv32", target_arch = "riscv64"),
    any(target_os = "linux", target_os = "android"),
    any(feature = "libc", feature = "use-syscall")
))]
#[inline(always)]
fn riscv_hwprobe() -> *mut core::ffi::c_void {
    let hwprobe: usize;
    unsafe {
        core::arch::asm!(
            ".weak __riscv_hwprobe",
            "la {hwprobe}, __riscv_hwprobe",
            hwprobe = out(reg) hwprobe,
            options(nostack)
        );
    }
    hwprobe as *mut core::ffi::c_void
}

#[cfg(all(
    target_arch = "loongarch64",
    any(target_os = "linux", target_os = "android"),
    any(feature = "libc", feature = "use-syscall")
))]
#[inline(always)]
unsafe fn resolve_native_ifunc(ptr: NonNull<u8>) -> Result<VmAddr> {
    const AT_HWCAP: usize = 16;

    #[repr(C)]
    struct IfuncArg {
        size: usize,
        hwcap: usize,
    }

    let arg = IfuncArg {
        size: core::mem::size_of::<IfuncArg>(),
        hwcap: crate::os::getauxval(AT_HWCAP),
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
        any(feature = "libc", feature = "use-syscall")
    ),
    all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android"),
        any(feature = "libc", feature = "use-syscall")
    ),
    all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        any(target_os = "linux", target_os = "android"),
        any(feature = "libc", feature = "use-syscall")
    ),
    all(
        target_arch = "loongarch64",
        any(target_os = "linux", target_os = "android"),
        any(feature = "libc", feature = "use-syscall")
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
}

impl<Arch: RelocationArch> CodeExecutor<Arch> for NativeCodeExecutor {
    #[inline]
    fn call_lifecycle(&self, ctx: CodeContext<'_, Arch>, function: VmAddr) -> Result<()> {
        Self::ensure_supported::<Arch>()?;
        let ptr = ctx.host_ptr(function)?;
        unsafe { call_native_no_args(ptr) };
        Ok(())
    }

    #[inline]
    fn resolve_ifunc(&self, ctx: CodeContext<'_, Arch>, resolver: VmAddr) -> Result<VmAddr> {
        Self::ensure_supported::<Arch>()?;
        let ptr = ctx.host_ptr(resolver)?;
        debug_assert!(Arch::SUPPORTS_NATIVE_RUNTIME);
        unsafe { resolve_native_ifunc(ptr) }
    }

    #[inline]
    fn resolve_tls(
        &self,
        _ctx: CodeContext<'_, Arch>,
        resolver: VmAddr,
        index: TlsIndex,
    ) -> Result<VmAddr> {
        Self::ensure_supported::<Arch>()?;
        debug_assert!(Arch::SUPPORTS_NATIVE_RUNTIME);
        Ok(unsafe { resolve_native_tls(resolver, &index) })
    }
}
