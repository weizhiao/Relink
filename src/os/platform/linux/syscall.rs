use crate::input::{FileBacking, ModuleSourceId, Path};
#[cfg(target_pointer_width = "32")]
use crate::os::PageSize;
use crate::{
    Error, IoError, MmapError, Result, logging,
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, ProtFlags, SpaceInit, SpaceLayout},
};
use alloc::ffi::CString;
use core::{
    ffi::{c_int, c_void},
    mem::MaybeUninit,
};
use syscalls::Sysno;

/// Default raw-syscall mapping backend for Linux `use-syscall` builds.
#[derive(Clone, Copy, Default)]
pub struct DefaultMmap;

impl DefaultMmap {
    /// Creates the default raw-syscall mapping backend.
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
        from_ret(
            unsafe { raw_mmap(addr, len, prot, flags, fd, offset) },
            |code| code,
        )
        .map(VmAddr::new)
    }
}

pub(crate) fn current_thread_id() -> usize {
    unsafe { syscalls::raw_syscall!(Sysno::gettid) }
}

pub(crate) fn path_is_dir(path: &Path) -> bool {
    const AT_FDCWD: core::ffi::c_int = -100;
    const STATX_TYPE: u32 = 1;
    const S_IFMT: u16 = 0o170000;
    const S_IFDIR: u16 = 0o040000;

    let Ok(path) = CString::new(path) else {
        return false;
    };
    let mut stat = MaybeUninit::<Statx>::zeroed();
    let result = unsafe {
        syscalls::raw_syscall!(
            Sysno::statx,
            AT_FDCWD,
            path.as_ptr(),
            0,
            STATX_TYPE,
            stat.as_mut_ptr()
        )
    };
    if result != 0 {
        return false;
    }
    let stat = unsafe { stat.assume_init() };
    stat.mask & STATX_TYPE != 0 && stat.mode & S_IFMT == S_IFDIR
}

pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    core::ptr::null_mut()
}

#[inline]
#[allow(dead_code)]
pub(crate) fn getauxval(at: usize) -> usize {
    try_getauxval(at).unwrap_or(0)
}

#[inline]
fn try_getauxval(at: usize) -> Result<usize> {
    const AT_NULL: usize = 0;
    const AUXV_PATH: &str = "/proc/self/auxv";

    let file = RawFile::from_path(Path::new(AUXV_PATH))?;
    let mut bytes = [0u8; 4096];
    let len = file.read_some(&mut bytes, 0)?;

    let entry_len = core::mem::size_of::<usize>() * 2;
    let mut offset = 0;
    while offset + entry_len <= len {
        let key = unsafe { (bytes.as_ptr().add(offset) as *const usize).read_unaligned() };
        let value = unsafe {
            (bytes.as_ptr().add(offset + core::mem::size_of::<usize>()) as *const usize)
                .read_unaligned()
        };
        if key == AT_NULL {
            break;
        }
        if key == at {
            return Ok(value);
        }
        offset += entry_len;
    }

    Ok(0)
}

pub(crate) struct RawFile {
    fd: isize,
}

#[repr(C)]
struct StatxTimestamp {
    seconds: i64,
    nanoseconds: u32,
    reserved: i32,
}

#[repr(C)]
struct Statx {
    mask: u32,
    block_size: u32,
    attributes: u64,
    links: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    reserved: u16,
    inode: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    access_time: StatxTimestamp,
    birth_time: StatxTimestamp,
    change_time: StatxTimestamp,
    modified_time: StatxTimestamp,
    rdev_major: u32,
    rdev_minor: u32,
    dev_major: u32,
    dev_minor: u32,
    mount_id: u64,
    direct_io_memory_alignment: u32,
    direct_io_offset_alignment: u32,
    spare: [u64; 12],
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    #[inline]
    fn file_backing(&self, backing: FileBacking) -> Result<Option<FileBacking>> {
        backing.for_mapping(self.page_size().bytes())
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
        from_ret(
            unsafe { syscalls::raw_syscall!(Sysno::munmap, addr.as_mut_ptr::<c_void>(), len) },
            |code| Error::from(MmapError::MunmapFailed { code }),
        )
        .map(|_| ())
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
            |code| Error::from(MmapError::Madvise { code }),
        )?;
        Ok(())
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        from_ret(
            syscalls::raw_syscall!(
                Sysno::mprotect,
                addr.as_mut_ptr::<c_void>(),
                len,
                prot.bits()
            ),
            |code| Error::from(MmapError::Mprotect { code }),
        )?;
        Ok(())
    }
}

/// Invokes the native mmap ABI with a byte offset on every architecture.
#[inline]
unsafe fn raw_mmap(
    addr: VmAddr,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: isize,
    offset: usize,
) -> usize {
    #[cfg(target_pointer_width = "32")]
    let (syscall, offset) = (Sysno::mmap2, offset / PageSize::BASE_BYTES);
    #[cfg(not(target_pointer_width = "32"))]
    let syscall = Sysno::mmap;
    unsafe {
        syscalls::raw_syscall!(
            syscall,
            addr.as_mut_ptr::<c_void>(),
            len,
            prot.bits(),
            flags.bits(),
            fd as c_int,
            offset
        )
    }
}

#[inline(always)]
fn from_ret<E, F>(value: usize, make_error: F) -> core::result::Result<usize, E>
where
    F: FnOnce(u32) -> E,
{
    if value > -4096isize as usize {
        // Truncation of the error value is guaranteed to never occur due to
        // the above check. This is the same check that musl uses:
        // https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
        Err(make_error((-(value as isize)) as u32))
    } else {
        Ok(value)
    }
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
    pub(crate) fn from_owned_fd(raw_fd: i32) -> Result<Self> {
        Ok(Self {
            fd: raw_fd as isize,
        })
    }

    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        const RDONLY: u32 = 0;
        let c_path = CString::new(path).map_err(|_| IoError::NullByteInPath)?;
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let result = unsafe { syscalls::raw_syscall!(Sysno::open, c_path.as_ptr(), RDONLY, 0) };
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        ))]
        let result = unsafe {
            const AT_FDCWD: core::ffi::c_int = -100;
            syscalls::raw_syscall!(Sysno::openat, AT_FDCWD, c_path.as_ptr(), RDONLY, 0)
        };
        let fd = from_ret(result, |code| {
            Error::from(IoError::OpenFailed {
                path: path.as_bytes().into(),
                code,
            })
        })?;
        Self::from_owned_fd(fd as i32)
    }

    pub(crate) fn metadata(&self) -> Result<(usize, ModuleSourceId)> {
        let fd = self.fd;
        const AT_EMPTY_PATH: usize = 0x1000;
        const STATX_BASIC_STATS: usize = 0x07ff;
        const STATX_INO: u32 = 0x0100;
        const STATX_SIZE: u32 = 0x0200;
        const SEEK_END: u32 = 2;

        let mut stat = MaybeUninit::<Statx>::zeroed();
        let result = unsafe {
            syscalls::raw_syscall!(
                Sysno::statx,
                fd,
                c"".as_ptr(),
                AT_EMPTY_PATH,
                STATX_BASIC_STATS,
                stat.as_mut_ptr()
            )
        };
        let mut source_id = None;
        if result == 0 {
            let stat = unsafe { stat.assume_init() };
            if stat.mask & STATX_INO != 0 {
                let volume = (u64::from(stat.dev_major) << 32) | u64::from(stat.dev_minor);
                source_id = Some(ModuleSourceId::file(volume, u128::from(stat.inode)));
            }
            if stat.mask & STATX_SIZE != 0 {
                let len = usize::try_from(stat.size).map_err(|_| IoError::ReadBufferTooLarge)?;
                return Ok((len, source_id.unwrap_or_else(ModuleSourceId::fresh)));
            }
        }

        let len = unsafe {
            from_ret(
                syscalls::raw_syscall!(Sysno::lseek, fd, 0, SEEK_END),
                |code| Error::from(IoError::SeekFailed { code }),
            )
        }?;
        Ok((len, source_id.unwrap_or_else(ModuleSourceId::fresh)))
    }

    fn read_some(&self, bytes: &mut [u8], offset: usize) -> Result<usize> {
        from_ret(
            unsafe { pread64(self.fd, bytes.as_mut_ptr(), bytes.len(), offset) },
            |code| Error::from(IoError::ReadFailed { code }),
        )
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        let res = unsafe {
            from_ret(syscalls::raw_syscall!(Sysno::close, self.fd), |_code| {
                Error::from(IoError::CloseFailed)
            })
        };
        debug_assert!(res.is_ok(), "failed to close ELF file");
        if let Err(err) = res {
            logging::error!("failed to close ELF file: {err}");
        }
    }
}

impl RawFile {
    pub(crate) fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        super::read_exact_at(buf, offset, |bytes, offset| self.read_some(bytes, offset))
    }

    pub(crate) fn mapping_handle(&self) -> isize {
        self.fd
    }
}
