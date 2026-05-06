use crate::input::ElfReader;
use crate::{
    Error, IoError, MmapError, Result, logging,
    os::{MadviseAdvice, MapFlags, Mmap, ProtFlags},
};
use alloc::ffi::CString;
use core::ffi::{c_int, c_void};
use syscalls::Sysno;

/// An implementation of Mmap trait
pub struct DefaultMmap;

#[cfg(feature = "tls")]
pub(crate) fn current_thread_id() -> usize {
    unsafe { syscalls::raw_syscall!(Sysno::gettid) }
}

#[cfg(feature = "tls")]
pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

#[cfg(feature = "tls")]
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
        let (syscall, offset) = (
            Sysno::mmap2,
            offset / crate::os::PageSize::BASE_BYTES as isize,
        );
        #[cfg(not(target_pointer_width = "32"))]
        let syscall = Sysno::mmap;
        from_ret(
            syscalls::raw_syscall!(syscall, addr, len, prot.bits(), flags.bits(), fd, offset),
            |code| MmapError::MmapFailed { code }.into(),
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
            |code| MmapError::MmapAnonymousFailed { code }.into(),
        )?
    };
    Ok(ptr as *mut c_void)
}

#[inline]
fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
    unsafe {
        from_ret(syscalls::raw_syscall!(Sysno::munmap, addr, len), |code| {
            MmapError::MunmapFailed { code }.into()
        })?;
    }
    Ok(())
}

#[inline]
fn mprotect(addr: *mut c_void, len: usize, prot: ProtFlags) -> Result<()> {
    unsafe {
        from_ret(
            syscalls::raw_syscall!(Sysno::mprotect, addr, len, prot.bits()),
            |code| MmapError::Mprotect { code }.into(),
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

    #[inline]
    unsafe fn madvise(addr: *mut c_void, len: usize, behavior: MadviseAdvice) -> Result<()> {
        from_ret(
            syscalls::raw_syscall!(Sysno::madvise, addr, len, behavior as c_int),
            |code| MmapError::Madvise { code }.into(),
        )?;
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
fn from_ret<F>(value: usize, make_error: F) -> Result<usize>
where
    F: FnOnce(u32) -> Error,
{
    if value > -4096isize as usize {
        // Truncation of the error value is guaranteed to never occur due to
        // the above check. This is the same check that musl uses:
        // https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
        return Err(make_error((-(value as isize)) as u32));
    }
    Ok(value)
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
        let name = CString::new(path).map_err(|_| IoError::NullByteInPath)?;
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let fd = unsafe {
            let res = syscalls::raw_syscall!(Sysno::open, name.as_ptr(), RDONLY, 0);
            if res > -4096isize as usize {
                return Err(IoError::OpenFailed {
                    path: path.into(),
                    code: (-(res as isize)) as u32,
                }
                .into());
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
                return Err(IoError::OpenFailed {
                    path: path.into(),
                    code: (-(res as isize)) as u32,
                }
                .into());
            }
            res
        };
        Ok(RawFile { fd: fd as _, name })
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        let res = unsafe {
            from_ret(syscalls::raw_syscall!(Sysno::close, self.fd), |_code| {
                IoError::CloseFailed.into()
            })
        };
        debug_assert!(res.is_ok(), "failed to close ELF file");
        if let Err(err) = res {
            logging::error!("failed to close ELF file: {err}");
        }
    }
}

impl ElfReader for RawFile {
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        const SEEK_START: u32 = 0;
        unsafe {
            from_ret(
                syscalls::raw_syscall!(Sysno::lseek, self.fd, offset, SEEK_START),
                |code| IoError::SeekFailed { code }.into(),
            )?;
            let size = from_ret(
                syscalls::raw_syscall!(Sysno::read, self.fd, buf.as_mut_ptr(), buf.len()),
                |code| IoError::ReadFailed { code }.into(),
            )?;
            if size != buf.len() {
                return Err(IoError::FailedToFillBuffer.into());
            }
        }
        Ok(())
    }

    fn file_name(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(self.name.as_bytes()) }
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.fd as isize)
    }
}
