use crate::input::{ElfReader, Path, PathBuf};
use crate::{
    Error, IoError, MmapError, Result, logging,
    os::{MadviseAdvice, MapFlags, MappedRegion, Mmap, ProtFlags, VmAddr},
};
use alloc::ffi::CString;
use core::ffi::{c_int, c_void};
use syscalls::Sysno;

/// An implementation of Mmap trait
#[derive(Clone, Copy, Default)]
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
    path: PathBuf,
    fd: isize,
}

impl Mmap for DefaultMmap {
    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        _populate_later: bool,
    ) -> crate::Result<MappedRegion> {
        let ptr = unsafe {
            #[cfg(target_pointer_width = "32")]
            let syscall = Sysno::mmap2;
            #[cfg(not(target_pointer_width = "32"))]
            let syscall = Sysno::mmap;
            from_ret(
                syscalls::raw_syscall!(
                    syscall,
                    addr.map_or(core::ptr::null_mut::<c_void>(), |addr| {
                        addr.as_mut_ptr::<c_void>()
                    }),
                    len,
                    prot.bits(),
                    (MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS).bits(),
                    usize::MAX,
                    0
                ),
                |code| MmapError::MmapAnonymousFailed { code }.into(),
            )? as *mut c_void
        };
        Ok(MappedRegion::local(ptr, len, *self))
    }

    unsafe fn map_file_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> crate::Result<()> {
        unsafe {
            #[cfg(target_pointer_width = "32")]
            let (syscall, offset) = (Sysno::mmap2, offset / crate::os::PageSize::BASE_BYTES);
            #[cfg(not(target_pointer_width = "32"))]
            let syscall = Sysno::mmap;
            from_ret(
                syscalls::raw_syscall!(
                    syscall,
                    addr.as_mut_ptr::<c_void>(),
                    len,
                    prot.bits(),
                    flags.bits(),
                    fd as c_int,
                    offset
                ),
                |code| MmapError::MmapFailed { code }.into(),
            )?;
        }
        Ok(())
    }

    unsafe fn map_copy_at(&self, addr: VmAddr, len: usize, flags: MapFlags) -> crate::Result<()> {
        unsafe {
            #[cfg(target_pointer_width = "32")]
            let syscall = Sysno::mmap2;
            #[cfg(not(target_pointer_width = "32"))]
            let syscall = Sysno::mmap;
            from_ret(
                syscalls::raw_syscall!(
                    syscall,
                    addr.as_mut_ptr::<c_void>(),
                    len,
                    ProtFlags::PROT_WRITE.bits(),
                    flags.union(MapFlags::MAP_ANONYMOUS).bits(),
                    usize::MAX,
                    0
                ),
                |code| MmapError::MmapAnonymousFailed { code }.into(),
            )?;
        }
        Ok(())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> crate::Result<()> {
        unsafe {
            #[cfg(target_pointer_width = "32")]
            let syscall = Sysno::mmap2;
            #[cfg(not(target_pointer_width = "32"))]
            let syscall = Sysno::mmap;
            from_ret(
                syscalls::raw_syscall!(
                    syscall,
                    addr.as_mut_ptr::<c_void>(),
                    len,
                    prot.bits(),
                    flags.union(MapFlags::MAP_ANONYMOUS).bits(),
                    usize::MAX,
                    0
                ),
                |code| MmapError::MmapAnonymousFailed { code }.into(),
            )?;
        }
        Ok(())
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> crate::Result<()> {
        from_ret(
            syscalls::raw_syscall!(Sysno::munmap, addr.as_mut_ptr::<c_void>(), len),
            |code| MmapError::MunmapFailed { code }.into(),
        )?;
        Ok(())
    }

    #[inline]
    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()> {
        from_ret(
            syscalls::raw_syscall!(
                Sysno::madvise,
                addr.as_mut_ptr::<c_void>(),
                len,
                behavior as c_int
            ),
            |code| MmapError::Madvise { code }.into(),
        )?;
        Ok(())
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> crate::Result<()> {
        from_ret(
            syscalls::raw_syscall!(
                Sysno::mprotect,
                addr.as_mut_ptr::<c_void>(),
                len,
                prot.bits()
            ),
            |code| MmapError::Mprotect { code }.into(),
        )?;
        Ok(())
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
    pub(crate) fn from_owned_fd(path: &Path, raw_fd: i32) -> Self {
        Self {
            path: PathBuf::from(path),
            fd: raw_fd as isize,
        }
    }

    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        const RDONLY: u32 = 0;
        let path_str = path.as_str();
        let c_path = CString::new(path_str).map_err(|_| IoError::NullByteInPath)?;
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let fd = unsafe {
            let res = syscalls::raw_syscall!(Sysno::open, c_path.as_ptr(), RDONLY, 0);
            if res > -4096isize as usize {
                return Err(IoError::OpenFailed {
                    path: path_str.into(),
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
            let res = syscalls::raw_syscall!(Sysno::openat, AT_FDCWD, c_path.as_ptr(), RDONLY, 0);
            if res > -4096isize as usize {
                return Err(IoError::OpenFailed {
                    path: path_str.into(),
                    code: (-(res as isize)) as u32,
                }
                .into());
            }
            res
        };
        Ok(RawFile {
            path: PathBuf::from(path),
            fd: fd as _,
        })
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

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.fd as isize)
    }
}
