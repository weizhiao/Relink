use crate::{
    IoError, MmapError, Result,
    input::{FileBacking, ModuleSourceId, Path},
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags, SpaceInit, SpaceLayout},
};
use alloc::ffi::CString;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use libc::{_SC_PAGESIZE, O_RDONLY, madvise, mmap, mprotect, munmap, pread, sysconf};

#[inline]
fn last_os_error_code() -> u32 {
    // bionic exposes __errno() rather than glibc's __errno_location().
    #[cfg(target_os = "android")]
    unsafe {
        *libc::__errno() as u32
    }
    #[cfg(not(target_os = "android"))]
    unsafe {
        *libc::__errno_location() as u32
    }
}

#[inline]
#[allow(dead_code)]
pub(crate) fn getauxval(at: usize) -> usize {
    unsafe { libc::getauxval(at as libc::c_ulong) as usize }
}

/// Default libc-backed mapping backend for Linux builds.
#[derive(Clone, Copy, Default)]
pub struct DefaultMmap;

impl DefaultMmap {
    /// Creates the default libc-backed mmap implementation.
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    #[inline]
    pub(super) unsafe fn map(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: isize,
        offset: usize,
    ) -> core::result::Result<VmAddr, u32> {
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
            return Err(last_os_error_code());
        }
        Ok(VmAddr::from_ptr(ptr))
    }
}

pub(crate) fn current_thread_id() -> usize {
    unsafe { libc::pthread_self() as usize }
}

pub(crate) fn path_is_dir(path: &Path) -> bool {
    let Ok(path) = CString::new(path) else {
        return false;
    };
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::stat(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR
}

static TLS_CLEANUP_KEY: AtomicUsize = AtomicUsize::new(0);

/// Registers a destructor that will be called when the current thread exits.
/// This is used to clean up thread-local storage and also sets the initial value.
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

pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    let key = TLS_CLEANUP_KEY.load(Ordering::Acquire);
    if key == 0 {
        return core::ptr::null_mut();
    }
    unsafe { libc::pthread_getspecific((key - 1) as libc::pthread_key_t) }
}

pub(crate) struct RawFile {
    fd: isize,
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    #[inline]
    fn file_backing(&self, backing: FileBacking) -> Result<Option<FileBacking>> {
        backing.for_mapping(self.page_size().bytes())
    }

    #[inline]
    fn page_size(&self) -> PageSize {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) };
        if page_size <= 0 {
            PageSize::Base
        } else {
            PageSize::new(page_size as usize).unwrap_or_default()
        }
    }

    unsafe fn create_space(
        &self,
        layout: SpaceLayout,
        prot: ProtFlags,
        init: SpaceInit,
    ) -> Result<MappedRegion<Self::Region>> {
        unsafe { super::create_space(self, layout, prot, init) }
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        // SAFETY: the caller guarantees the existing mapping remains valid.
        Ok(unsafe { MappedRegion::local_alias(addr.as_mut_ptr(), len, *self) })
    }

    unsafe fn map_file_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()> {
        unsafe { self.map(addr, len, prot, flags, fd, offset) }
            .map(|_| ())
            .map_err(|code| MmapError::MmapFailed { code }.into())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<()> {
        unsafe { self.map(addr, len, prot, flags | MapFlags::MAP_ANONYMOUS, -1, 0) }
            .map(|_| ())
            .map_err(|code| MmapError::MmapAnonymousFailed { code }.into())
    }

    /// Releases an owned mapping or a page-aligned subrange of it.
    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        if unsafe { munmap(addr.as_mut_ptr(), len) } != 0 {
            return Err(MmapError::MunmapFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(())
    }

    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()> {
        let res = unsafe { madvise(addr.as_mut_ptr(), len, behavior as _) };
        if res != 0 {
            return Err(MmapError::Madvise {
                code: last_os_error_code(),
            }
            .into());
        }
        Ok(())
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
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
        let name = CString::new(path).map_err(|_| IoError::NullByteInPath)?;
        let fd = unsafe { libc::open(name.as_ptr(), O_RDONLY) };
        if fd == -1 {
            return Err(IoError::OpenFailed {
                path: path.as_bytes().into(),
                code: last_os_error_code(),
            }
            .into());
        }
        Self::from_owned_fd(fd as i32)
    }

    pub(crate) fn from_owned_fd(raw_fd: i32) -> Result<Self> {
        Ok(Self {
            fd: raw_fd as isize,
        })
    }

    pub(crate) fn metadata(&self) -> Result<(usize, ModuleSourceId)> {
        let fd = self.fd;
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd as i32, stat.as_mut_ptr()) } != 0 {
            return Err(IoError::FileInfoFailed {
                code: last_os_error_code(),
            }
            .into());
        }
        let stat = unsafe { stat.assume_init() };
        let len = usize::try_from(stat.st_size).map_err(|_| IoError::ReadBufferTooLarge)?;
        let source_id = ModuleSourceId::file(stat.st_dev as u64, stat.st_ino as u128);
        Ok((len, source_id))
    }
}

impl RawFile {
    pub(crate) fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        super::read_exact_at(buf, offset, |bytes, offset| {
            let result = unsafe {
                pread(
                    self.fd as i32,
                    bytes.as_mut_ptr() as *mut libc::c_void,
                    bytes.len(),
                    offset as _,
                )
            };

            if result < 0 {
                Err(IoError::ReadFailed {
                    code: last_os_error_code(),
                }
                .into())
            } else {
                Ok(result as usize)
            }
        })
    }

    pub(crate) fn mapping_handle(&self) -> isize {
        self.fd
    }
}
