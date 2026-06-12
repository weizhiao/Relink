use crate::input::{ElfReader, Path, PathBuf};
use crate::{
    Error, IoError, MmapError, Result, logging,
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, ProtFlags},
};
use alloc::{boxed::Box, ffi::CString};
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
    len: usize,
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        _populate_later: bool,
    ) -> crate::Result<MappedRegion<Self::Region>> {
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

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        Ok(MappedRegion::local_alias(addr.as_mut_ptr(), len, *self))
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

#[inline]
unsafe fn pread64(fd: isize, buf: *mut u8, len: usize, offset: usize) -> usize {
    #[cfg(target_pointer_width = "64")]
    {
        unsafe { syscalls::raw_syscall!(Sysno::pread64, fd, buf, len, offset) }
    }

    #[cfg(all(
        target_pointer_width = "32",
        any(target_arch = "arm", target_arch = "mips", target_arch = "mips32r6")
    ))]
    {
        let offset = offset as u64;
        let hi = (offset >> 32) as usize;
        let lo = offset as usize;
        unsafe { syscalls::raw_syscall!(Sysno::pread64, fd, buf, len, 0, lo, hi) }
    }

    #[cfg(all(
        target_pointer_width = "32",
        not(any(target_arch = "arm", target_arch = "mips", target_arch = "mips32r6"))
    ))]
    {
        let offset = offset as u64;
        let hi = (offset >> 32) as usize;
        let lo = offset as usize;
        unsafe { syscalls::raw_syscall!(Sysno::pread64, fd, buf, len, lo, hi) }
    }
}

impl RawFile {
    pub(crate) fn from_owned_fd(path: &Path, raw_fd: i32) -> Result<Self> {
        let fd = raw_fd as isize;
        Ok(Self {
            path: PathBuf::from(path),
            fd,
            len: Self::query_len(fd)?,
        })
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
        let fd = fd as isize;
        Ok(RawFile {
            path: PathBuf::from(path),
            fd,
            len: Self::query_len(fd)?,
        })
    }

    fn query_len(fd: isize) -> Result<usize> {
        const SEEK_END: u32 = 2;
        unsafe {
            from_ret(
                syscalls::raw_syscall!(Sysno::lseek, fd, 0, SEEK_END),
                |code| IoError::SeekFailed { code }.into(),
            )
        }
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
    fn len(&self) -> usize {
        self.len
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        let mut bytes = buf;
        let mut offset = offset;
        unsafe {
            while !bytes.is_empty() {
                let size = from_ret(
                    pread64(self.fd, bytes.as_mut_ptr(), bytes.len(), offset),
                    |code| IoError::ReadFailed { code }.into(),
                )?;
                if size == 0 {
                    return Err(IoError::FailedToFillBuffer.into());
                }
                offset = offset.checked_add(size).ok_or_else(|| {
                    IoError::ReadOutOfBounds(Box::new(crate::ReadBoundsError::new(
                        offset,
                        bytes.len(),
                        usize::MAX,
                    )))
                })?;
                bytes = &mut bytes[size..];
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
