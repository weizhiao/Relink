use crate::{
    IoError, MmapError, Result,
    input::{ModuleSourceId, Path},
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags, SpaceInit, SpaceLayout},
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

/// Default mapping backend for Linux/Android `std` builds.
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

pub(crate) fn path_is_dir(path: &Path) -> bool {
    std::path::Path::new(OsStr::from_bytes(path.as_bytes())).is_dir()
}

pub(crate) struct RawFile {
    file: File,
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    #[inline]
    fn page_size(&self) -> PageSize {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) };
        if page_size <= 0 {
            PageSize::Base
        } else {
            PageSize::new(page_size as usize).unwrap_or_default()
        }
    }

    fn thp_page_size(&self) -> Option<PageSize> {
        super::thp_page_size()
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
