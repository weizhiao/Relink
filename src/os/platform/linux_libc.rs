use crate::{
    IoError, MmapError, Result,
    input::{ElfReader, Path, PathBuf},
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags},
};
use alloc::{boxed::Box, ffi::CString};
use core::ffi::c_void;
#[cfg(feature = "tls")]
use core::sync::atomic::{AtomicUsize, Ordering};
use libc::{_SC_PAGESIZE, O_RDONLY, SEEK_END, madvise, mmap, mprotect, munmap, pread, sysconf};

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
    len: usize,
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    #[inline]
    fn page_size(&self) -> PageSize {
        self.page_size
    }

    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        _populate_later: bool,
    ) -> crate::Result<MappedRegion<Self::Region>> {
        let ptr = unsafe {
            mmap(
                addr.map_or(core::ptr::null_mut(), VmAddr::as_mut_ptr),
                len,
                prot.bits(),
                (MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS).bits(),
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
        let ptr = unsafe {
            mmap(
                addr.as_mut_ptr(),
                len,
                prot.bits(),
                flags.bits(),
                fd as i32,
                offset as _,
            )
        };
        if core::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(MmapError::MmapFailed {
                code: last_os_error_code(),
            }
            .into());
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
        Ok(())
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
        let fd = fd as isize;
        Ok(Self {
            path: PathBuf::from(path),
            fd,
            len: Self::query_len(fd)?,
        })
    }

    pub(crate) fn from_owned_fd(path: &Path, raw_fd: i32) -> Result<Self> {
        let fd = raw_fd as isize;
        Ok(Self {
            path: PathBuf::from(path),
            fd,
            len: Self::query_len(fd)?,
        })
    }

    fn query_len(fd: isize) -> Result<usize> {
        let off = unsafe { libc::lseek(fd as i32, 0, SEEK_END) };
        if off < 0 {
            return Err(IoError::SeekFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(off as usize)
    }
}

fn pread_exact(fd: i32, mut bytes: &mut [u8], mut offset: usize) -> Result<()> {
    loop {
        if bytes.is_empty() {
            return Ok(());
        }
        let bytes_to_read = bytes.len();
        let ptr = bytes.as_mut_ptr() as *mut libc::c_void;
        let result = unsafe { pread(fd, ptr, bytes_to_read, offset as _) };

        if result < 0 {
            return Err(IoError::ReadFailed {
                code: last_os_error_code(),
            }
            .into());
        } else if result == 0 {
            return Err(IoError::FailedToFillBuffer.into());
        }
        let n = result as usize;
        offset = offset
            .checked_add(n)
            .ok_or(IoError::ReadOutOfBounds(Box::new(
                crate::ReadBoundsError::new(offset, bytes_to_read, usize::MAX),
            )))?;
        bytes = &mut bytes[n..];
    }
}

impl ElfReader for RawFile {
    fn len(&self) -> usize {
        self.len
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        pread_exact(self.fd as i32, buf, offset)
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.fd)
    }
}
