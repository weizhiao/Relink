use crate::{
    IoError, MmapError, Result,
    input::{ModuleSourceId, Path},
    memory::VmAddr,
    os::{MadviseAdvice, MapFlags, PageSize, ProtFlags},
};
use libc::{_SC_PAGESIZE, madvise, mmap, mprotect, munmap, sysconf};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
};

#[inline]
fn last_os_error_code() -> u32 {
    os_error_code(&io::Error::last_os_error())
}

fn os_error_code(error: &io::Error) -> u32 {
    error.raw_os_error().unwrap_or(libc::EIO) as u32
}

#[inline]
#[allow(dead_code)]
pub(crate) fn getauxval(at: usize) -> usize {
    unsafe { libc::getauxval(at as libc::c_ulong) as usize }
}

#[inline]
pub(super) unsafe fn map(
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

pub(crate) fn path_is_dir(path: &Path) -> bool {
    std::path::Path::new(OsStr::from_bytes(path.as_bytes())).is_dir()
}

pub(crate) struct RawFile {
    file: File,
}

#[inline]
pub(super) fn page_size() -> PageSize {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size <= 0 {
        PageSize::Base
    } else {
        PageSize::new(page_size as usize).unwrap_or_default()
    }
}

/// Releases an owned mapping or a page-aligned subrange of it.
pub(super) unsafe fn unmap(addr: VmAddr, len: usize) -> Result<()> {
    if unsafe { munmap(addr.as_mut_ptr(), len) } != 0 {
        return Err(MmapError::MunmapFailed {
            code: last_os_error_code(),
        }
        .into());
    }
    Ok(())
}

pub(super) unsafe fn advise(addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()> {
    let res = unsafe { madvise(addr.as_mut_ptr(), len, behavior as _) };
    if res != 0 {
        return Err(MmapError::Madvise {
            code: last_os_error_code(),
        }
        .into());
    }
    Ok(())
}

pub(super) unsafe fn protect(addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
    let res = unsafe { mprotect(addr.as_mut_ptr(), len, prot.bits()) };
    if res != 0 {
        return Err(MmapError::Mprotect {
            code: last_os_error_code(),
        }
        .into());
    }
    Ok(())
}

impl RawFile {
    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        if path.as_bytes().contains(&0) {
            return Err(IoError::NullByteInPath.into());
        }
        let file = File::open(OsStr::from_bytes(path.as_bytes())).map_err(|error| {
            IoError::OpenFailed {
                path: path.as_bytes().into(),
                code: os_error_code(&error),
            }
        })?;
        Ok(Self { file })
    }

    pub(crate) fn from_owned_fd(raw_fd: i32) -> Result<Self> {
        // SAFETY: the caller transfers a valid, uniquely owned descriptor.
        Ok(Self {
            file: unsafe { File::from_raw_fd(raw_fd) },
        })
    }

    pub(crate) fn metadata(&self) -> Result<(usize, ModuleSourceId)> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| IoError::FileInfoFailed {
                code: os_error_code(&error),
            })?;
        let len = usize::try_from(metadata.len()).map_err(|_| IoError::ReadBufferTooLarge)?;
        let source_id = ModuleSourceId::file(metadata.dev(), metadata.ino() as u128);
        Ok((len, source_id))
    }

    pub(crate) fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        super::read_exact_at(buf, offset, |bytes, offset| self.read_some(bytes, offset))
    }

    pub(super) fn read_some(&self, bytes: &mut [u8], offset: usize) -> Result<usize> {
        loop {
            match self.file.read_at(bytes, offset as u64) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    return result.map_err(|error| {
                        IoError::ReadFailed {
                            code: os_error_code(&error),
                        }
                        .into()
                    });
                }
            }
        }
    }

    pub(crate) fn mapping_handle(&self) -> isize {
        self.file.as_raw_fd() as isize
    }
}
