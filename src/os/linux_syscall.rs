use crate::input::ElfReader;
use crate::{Error, io_error};
use crate::{
    Result,
    os::{MapFlags, Mmap, ProtFlags},
};
use alloc::{ffi::CString, format};
use core::ffi::{c_int, c_void};
use syscalls::Sysno;
/// An implementation of Mmap trait
pub struct DefaultMmap;

pub(crate) fn current_thread_id() -> usize {
    unsafe { syscalls::raw_syscall!(Sysno::gettid) }
}

pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    core::ptr::null_mut()
}

pub(crate) struct RawFile {
    name: CString,
    fd: isize,
}

#[inline]
fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: c_int,
    offset: isize,
) -> Result<*mut c_void> {
    let ptr = unsafe {
        #[cfg(target_pointer_width = "32")]
        let (syscall, offset) = (Sysno::mmap2, offset / crate::segment::PAGE_SIZE as isize);
        #[cfg(not(target_pointer_width = "32"))]
        let syscall = Sysno::mmap;
        from_ret(
            syscalls::raw_syscall!(syscall, addr, len, prot.bits(), flags.bits(), fd, offset),
            "mmap failed",
        )?
    };
    Ok(ptr as *mut c_void)
}

#[inline]
fn mmap_anonymous(
    addr: *mut c_void,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
) -> Result<*mut c_void> {
    let ptr = unsafe {
        #[cfg(target_pointer_width = "32")]
        let syscall = Sysno::mmap2;
        #[cfg(not(target_pointer_width = "32"))]
        let syscall = Sysno::mmap;
        from_ret(
            syscalls::raw_syscall!(
                syscall,
                addr,
                len,
                prot.bits(),
                flags.union(MapFlags::MAP_ANONYMOUS).bits(),
                usize::MAX,
                0
            ),
            "mmap anonymous",
        )?
    };
    Ok(ptr as *mut c_void)
}

#[inline]
fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
    unsafe {
        from_ret(
            syscalls::raw_syscall!(Sysno::munmap, addr, len),
            "munmap failed",
        )?;
    }
    Ok(())
}

#[inline]
fn mprotect(addr: *mut c_void, len: usize, prot: ProtFlags) -> Result<()> {
    unsafe {
        from_ret(
            syscalls::raw_syscall!(Sysno::mprotect, addr, len, prot.bits()),
            "mprotect failed",
        )?;
    }
    Ok(())
}

impl Mmap for DefaultMmap {
    unsafe fn mmap(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: Option<isize>,
        need_copy: &mut bool,
    ) -> crate::Result<*mut core::ffi::c_void> {
        let ptr = if let Some(fd) = fd {
            mmap(
                addr.unwrap_or(0) as _,
                len,
                prot,
                flags,
                fd as i32,
                offset as _,
            )?
        } else {
            *need_copy = true;
            addr.unwrap() as _
        };
        Ok(ptr)
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> crate::Result<*mut core::ffi::c_void> {
        let ptr = mmap_anonymous(addr as _, len, prot, flags)?;
        Ok(ptr)
    }

    unsafe fn munmap(addr: *mut core::ffi::c_void, len: usize) -> crate::Result<()> {
        munmap(addr, len)?;
        Ok(())
    }

    unsafe fn mprotect(
        addr: *mut core::ffi::c_void,
        len: usize,
        prot: ProtFlags,
    ) -> crate::Result<()> {
        mprotect(addr, len, prot)?;
        Ok(())
    }

    unsafe fn mmap_reserve(
        addr: Option<usize>,
        len: usize,
        use_file: bool,
    ) -> Result<*mut core::ffi::c_void> {
        let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        let prot = if use_file {
            ProtFlags::PROT_NONE
        } else {
            ProtFlags::PROT_WRITE
        };
        let ptr = mmap_anonymous(addr.unwrap_or(0) as _, len, prot, flags)?;
        Ok(ptr)
    }
}

/// Converts a raw syscall return value to a result.
#[inline(always)]
fn from_ret(value: usize, msg: &'static str) -> Result<usize> {
    if value > -4096isize as usize {
        // Truncation of the error value is guaranteed to never occur due to
        // the above check. This is the same check that musl uses:
        // https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
        return Err(map_error(msg));
    }
    Ok(value)
}

#[cold]
#[inline(never)]
fn map_error(msg: &'static str) -> Error {
    Error::Mmap { msg: msg.into() }
}

impl RawFile {
    pub(crate) fn from_owned_fd(path: &str, raw_fd: i32) -> Self {
        Self {
            name: CString::new(path).unwrap(),
            fd: raw_fd as isize,
        }
    }

    pub(crate) fn from_path(path: &str) -> Result<Self> {
        const RDONLY: u32 = 0;
        let name = CString::new(path).map_err(|_| Error::Io {
            msg: "null byte in path".into(),
        })?;
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let fd = unsafe {
            let res = syscalls::raw_syscall!(Sysno::open, name.as_ptr(), RDONLY, 0);
            if res > -4096isize as usize {
                return Err(io_error(format!("open failed: {}", path)));
            }
            res
        };
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        ))]
        let fd = unsafe {
            const AT_FDCWD: core::ffi::c_int = -100;
            let res = syscalls::raw_syscall!(Sysno::openat, AT_FDCWD, name.as_ptr(), RDONLY, 0);
            if res > -4096isize as usize {
                return Err(io_error(format!("openat failed: {}", path)));
            }
            res
        };
        Ok(RawFile { fd: fd as _, name })
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        unsafe {
            from_io_ret(
                syscalls::raw_syscall!(Sysno::close, self.fd),
                "close failed",
            )
            .unwrap();
        }
    }
}

impl ElfReader for RawFile {
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        const SEEK_START: u32 = 0;
        unsafe {
            from_io_ret(
                syscalls::raw_syscall!(Sysno::lseek, self.fd, offset, SEEK_START),
                "lseek failed",
            )?;
            let size = from_io_ret(
                syscalls::raw_syscall!(Sysno::read, self.fd, buf.as_mut_ptr(), buf.len()),
                "read failed",
            )?;
            assert!(size == buf.len());
        }
        Ok(())
    }

    fn file_name(&self) -> &str {
        self.name.to_str().unwrap()
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.fd as isize)
    }
}
/// Converts a raw syscall return value to a result.
#[inline(always)]
fn from_io_ret(value: usize, msg: &'static str) -> Result<usize> {
    if value > -4096isize as usize {
        // Truncation of the error value is guaranteed to never occur due to
        // the above check. This is the same check that musl uses:
        // https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
        return Err(io_error(msg));
    }
    Ok(value)
}
