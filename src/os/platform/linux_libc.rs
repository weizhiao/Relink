use crate::{
    IoError, MmapError, Result,
    input::{ElfReader, Path, PathBuf},
    os::{MadviseAdvice, MapFlags, MappedRegion, Mmap, MmapResult, PageSize, ProtFlags, VmAddr},
};
use alloc::ffi::CString;
use core::ffi::c_void;
#[cfg(feature = "tls")]
use core::sync::atomic::{AtomicUsize, Ordering};
use libc::{_SC_PAGESIZE, O_RDONLY, SEEK_SET, madvise, mmap, mprotect, munmap, sysconf};

#[inline]
fn last_os_error_code() -> u32 {
    unsafe { *libc::__errno_location() as u32 }
}

/// An implementation of Mmap trait
#[derive(Clone, Copy)]
pub struct DefaultMmap {
    page_size: PageSize,
}

impl Default for DefaultMmap {
    fn default() -> Self {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) };
        let page_size = if page_size <= 0 {
            PageSize::Base
        } else {
            PageSize::new(page_size as usize).unwrap_or_default()
        };
        Self { page_size }
    }
}

#[cfg(feature = "tls")]
pub(crate) fn current_thread_id() -> usize {
    unsafe { libc::pthread_self() as usize }
}

#[cfg(feature = "tls")]
static TLS_CLEANUP_KEY: AtomicUsize = AtomicUsize::new(0);

/// Registers a destructor that will be called when the current thread exits.
/// This is used to clean up thread-local storage and also sets the initial value.
#[cfg(feature = "tls")]
pub(crate) unsafe fn register_thread_destructor(
    destructor: unsafe extern "C" fn(*mut c_void),
    value: *mut c_void,
) {
    let mut key = TLS_CLEANUP_KEY.load(Ordering::Acquire);

    // 1. Ensure the key is created
    if key == 0 {
        let mut new_key: libc::pthread_key_t = 0;
        if unsafe { libc::pthread_key_create(&mut new_key, Some(destructor)) } == 0 {
            let encoded = (new_key as usize).wrapping_add(1);
            match TLS_CLEANUP_KEY.compare_exchange(0, encoded, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => key = encoded,
                Err(actual) => {
                    unsafe { libc::pthread_key_delete(new_key) };
                    key = actual;
                }
            }
        }
    }

    // 2. Set thread-specific value to trigger destructor on exit
    if key != 0 {
        let actual_key = (key - 1) as libc::pthread_key_t;
        unsafe { libc::pthread_setspecific(actual_key, value) };
    }
}

#[cfg(feature = "tls")]
pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    let key = TLS_CLEANUP_KEY.load(Ordering::Acquire);
    if key == 0 {
        return core::ptr::null_mut();
    }
    unsafe { libc::pthread_getspecific((key - 1) as libc::pthread_key_t) }
}

pub(crate) struct RawFile {
    path: PathBuf,
    fd: isize,
}

impl Mmap for DefaultMmap {
    #[inline]
    fn page_size(&self) -> PageSize {
        self.page_size
    }

    unsafe fn mmap(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: Option<isize>,
    ) -> crate::Result<MmapResult> {
        let mut needs_copy = false;
        let ptr = if let Some(fd) = fd {
            unsafe {
                mmap(
                    addr.map_or(core::ptr::null_mut(), VmAddr::as_mut_ptr),
                    len,
                    prot.bits(),
                    flags.bits(),
                    fd as i32,
                    offset as _,
                )
            }
        } else {
            needs_copy = true;
            addr.unwrap().as_mut_ptr()
        };
        if core::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(MmapError::MmapFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(MmapResult::new(
            MappedRegion::local_alias(ptr, len, *self),
            needs_copy,
        ))
    }

    unsafe fn mmap_anonymous(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> crate::Result<MappedRegion> {
        let ptr = unsafe {
            mmap(
                addr.as_mut_ptr(),
                len,
                prot.bits(),
                flags.union(MapFlags::MAP_ANONYMOUS).bits(),
                -1,
                0,
            )
        };
        if core::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(MmapError::MmapAnonymousFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        let region = if flags.contains(MapFlags::MAP_FIXED) {
            MappedRegion::local_alias(ptr, len, *self)
        } else {
            MappedRegion::local(ptr, len, *self)
        };
        Ok(region)
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> crate::Result<()> {
        let res = unsafe { munmap(addr.as_mut_ptr(), len) };
        if res != 0 {
            return Err(MmapError::MunmapFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(())
    }

    unsafe fn madvise(
        &self,
        addr: VmAddr,
        len: usize,
        behavior: MadviseAdvice,
    ) -> crate::Result<()> {
        let res = unsafe { madvise(addr.as_mut_ptr(), len, behavior as _) };
        if res != 0 {
            return Err(MmapError::Madvise {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(())
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> crate::Result<()> {
        let res = unsafe { mprotect(addr.as_mut_ptr(), len, prot.bits()) };
        if res != 0 {
            return Err(MmapError::Mprotect {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(())
    }

    unsafe fn mmap_reserve(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        use_file: bool,
    ) -> Result<MappedRegion> {
        let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        let prot = if use_file {
            ProtFlags::PROT_NONE
        } else {
            ProtFlags::PROT_WRITE
        };
        let ptr = unsafe {
            mmap(
                addr.map_or(core::ptr::null_mut(), VmAddr::as_mut_ptr),
                len,
                prot.bits(),
                flags.bits(),
                -1,
                0,
            )
        };
        if core::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(MmapError::MmapAnonymousFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(MappedRegion::local(ptr, len, *self))
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd as i32) };
    }
}

impl RawFile {
    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        let path_str = path.as_str();
        let name = CString::new(path_str).map_err(|_| IoError::NullByteInPath)?;
        let fd = unsafe { libc::open(name.as_ptr(), O_RDONLY) };
        if fd == -1 {
            return Err(IoError::OpenFailed {
                path: path_str.into(),
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(Self {
            path: PathBuf::from(path),
            fd: fd as isize,
        })
    }

    pub(crate) fn from_owned_fd(path: &Path, raw_fd: i32) -> Self {
        Self {
            path: PathBuf::from(path),
            fd: raw_fd as isize,
        }
    }
}

fn lseek(fd: i32, offset: usize) -> Result<()> {
    let off = unsafe { libc::lseek(fd, offset as _, SEEK_SET) };
    if off == -1 || off as usize != offset {
        return Err(IoError::SeekFailed {
            code: last_os_error_code(),
        }
        .into());
    }
    Ok(())
}

fn read_exact(fd: i32, mut bytes: &mut [u8]) -> Result<()> {
    loop {
        if bytes.is_empty() {
            return Ok(());
        }
        // 尝试读取剩余的字节数
        let bytes_to_read = bytes.len();
        let ptr = bytes.as_mut_ptr() as *mut libc::c_void;
        let result = unsafe { libc::read(fd, ptr, bytes_to_read) };

        if result < 0 {
            // 出现错误
            return Err(IoError::ReadFailed {
                code: last_os_error_code(),
            }
            .into());
        } else if result == 0 {
            // 意外到达文件末尾
            return Err(IoError::FailedToFillBuffer.into());
        }
        // 成功读取了部分字节
        let n = result as usize;
        // 更新剩余需要读取的部分
        bytes = &mut bytes[n..];
    }
}

impl ElfReader for RawFile {
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        lseek(self.fd as i32, offset)?;
        read_exact(self.fd as i32, buf)?;
        Ok(())
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.fd)
    }
}
