use crate::{
    Error, Result,
    input::ElfReader,
    io_error,
    os::{MapFlags, Mmap, ProtFlags},
};
use alloc::{
    ffi::CString,
    format,
    string::{String, ToString},
};
use core::{
    ffi::c_void,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};
use libc::{O_RDONLY, SEEK_SET, mmap, mprotect, munmap};

/// An implementation of Mmap trait
pub struct DefaultMmap;

pub(crate) fn current_thread_id() -> usize {
    unsafe { libc::pthread_self() as usize }
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
    name: String,
    fd: isize,
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
    ) -> crate::Result<*mut c_void> {
        let ptr = if let Some(fd) = fd {
            unsafe {
                mmap(
                    addr.unwrap_or(0) as _,
                    len,
                    prot.bits(),
                    flags.bits(),
                    fd as i32,
                    offset as _,
                )
            }
        } else {
            *need_copy = true;
            addr.unwrap() as _
        };
        if core::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(map_error("mmap failed"));
        }
        Ok(ptr)
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> crate::Result<*mut c_void> {
        let ptr = unsafe {
            mmap(
                addr as _,
                len,
                prot.bits(),
                flags.union(MapFlags::MAP_ANONYMOUS).bits(),
                -1,
                0,
            )
        };
        if core::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(map_error("mmap anonymous failed"));
        }
        Ok(ptr)
    }

    unsafe fn munmap(addr: *mut c_void, len: usize) -> crate::Result<()> {
        let res = unsafe { munmap(addr, len) };
        if res != 0 {
            return Err(map_error("munmap failed"));
        }
        Ok(())
    }

    unsafe fn mprotect(addr: *mut c_void, len: usize, prot: ProtFlags) -> crate::Result<()> {
        let res = unsafe { mprotect(addr, len, prot.bits()) };
        if res != 0 {
            return Err(map_error("mprotect failed"));
        }
        Ok(())
    }

    unsafe fn mmap_reserve(addr: Option<usize>, len: usize, use_file: bool) -> Result<*mut c_void> {
        let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        let prot = if use_file {
            ProtFlags::PROT_NONE
        } else {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        };
        let ptr = unsafe {
            mmap(
                addr.unwrap_or(0) as _,
                len,
                prot.bits(),
                flags.bits(),
                -1,
                0,
            )
        };
        Ok(ptr)
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd as i32) };
    }
}

impl RawFile {
    pub(crate) fn from_path(path: &str) -> Result<Self> {
        let name = CString::from_str(path).unwrap();
        let fd = unsafe { libc::open(name.as_ptr(), O_RDONLY) };
        if fd == -1 {
            return Err(io_error(format!("open failed: {}", path)));
        }
        Ok(Self {
            name: path.to_string(),
            fd: fd as isize,
        })
    }

    pub(crate) fn from_owned_fd(path: &str, raw_fd: i32) -> Self {
        Self {
            name: path.to_string(),
            fd: raw_fd as isize,
        }
    }
}

fn lseek(fd: i32, offset: usize) -> Result<()> {
    let off = unsafe { libc::lseek(fd, offset as _, SEEK_SET) };
    if off == -1 || off as usize != offset {
        return Err(io_error("lseek failed"));
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
            return Err(io_error("read error"));
        } else if result == 0 {
            // 意外到达文件末尾
            return Err(io_error("failed to fill buffer"));
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

    fn file_name(&self) -> &str {
        &self.name
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.fd)
    }
}

#[cold]
#[inline(never)]
fn map_error(msg: &str) -> Error {
    Error::Mmap {
        msg: msg.to_string().into(),
    }
}
