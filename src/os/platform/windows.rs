use crate::{
    IoError, MmapError, Result,
    input::{FileBacking, ModuleSourceId, Path},
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags, SpaceInit, SpaceLayout},
};
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    mem::MaybeUninit,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GENERIC_EXECUTE, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, GetFileAttributesW, GetFileInformationByHandle, INVALID_FILE_ATTRIBUTES,
        OPEN_EXISTING, ReadFile,
    },
    System::Memory::{
        self as Memory, CreateFileMappingW, MEM_COMMIT, MEM_MAPPED, MEM_PRESERVE_PLACEHOLDER,
        MEM_PRIVATE, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER,
        MEMORY_BASIC_INFORMATION, MapViewOfFile3, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualFree, VirtualQuery,
    },
    System::Threading::GetCurrentProcess,
    System::{
        IO::{OVERLAPPED, OVERLAPPED_0_0},
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    },
};

#[derive(Clone, Copy, Default)]
pub struct DefaultMmap;

impl DefaultMmap {
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

fn query_memory(addr: usize) -> Result<MEMORY_BASIC_INFORMATION> {
    let mut info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
    if unsafe {
        VirtualQuery(
            addr as _,
            info.as_mut_ptr(),
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } == 0
    {
        return Err(MmapError::VirtualQuery {
            code: unsafe { GetLastError() },
        }
        .into());
    }
    Ok(unsafe { info.assume_init() })
}

fn region_end(info: &MEMORY_BASIC_INFORMATION) -> Result<usize> {
    (info.BaseAddress as usize)
        .checked_add(info.RegionSize)
        .filter(|end| *end > info.BaseAddress as usize)
        .ok_or_else(|| MmapError::InvalidMappedRegionRange.into())
}

/// Isolates a mapping range without releasing its address reservation.
/// The caller must own the enclosing placeholder created by `create_space`.
unsafe fn prepare_placeholder(addr: VmAddr, len: usize) -> Result<()> {
    let start = addr.get();
    let page_size = DefaultMmap.page_size().bytes();
    let end = start
        .checked_add(len)
        .filter(|_| len != 0 && start.is_multiple_of(page_size) && len.is_multiple_of(page_size))
        .ok_or(MmapError::InvalidMappedRegionRange)?;
    let info = query_memory(start)?;
    let base = info.AllocationBase as usize;
    let reserved_end = region_end(&info)?;
    if info.State != MEM_RESERVE
        || info.Type != MEM_PRIVATE
        || info.AllocationProtect != PAGE_NOACCESS
        || base > start
        || end > reserved_end
    {
        return Err(MmapError::InvalidMappedRegionRange.into());
    }

    // Split off the prefix first, leaving a placeholder starting at `start`.
    // These operations preserve both sides, including on a later mapping failure.
    if base < start {
        unsafe { split_placeholder(base, start - base) }?;
    }
    if end < reserved_end {
        unsafe { split_placeholder(start, len) }?;
    }
    Ok(())
}

unsafe fn split_placeholder(addr: usize, len: usize) -> Result<()> {
    if unsafe { VirtualFree(addr as _, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
        return Err(MmapError::VirtualFree {
            code: unsafe { GetLastError() },
        }
        .into());
    }
    Ok(())
}

pub(crate) fn current_thread_id() -> usize {
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as usize }
}

fn wide_path(path: &Path) -> Vec<u16> {
    let mut wide: Vec<_> = {
        if let Ok(path_str) = str::from_utf8(path.as_bytes()) {
            path_str.encode_utf16().collect()
        } else {
            #[cfg(feature = "std")]
            {
                use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

                // SAFETY: `Path` contains either UTF-8 or the encoded bytes of an `OsStr`, which is a superset of UTF-8.
                let os_str = unsafe { OsStr::from_encoded_bytes_unchecked(path.as_bytes()) };
                os_str.encode_wide().collect()
            }

            #[cfg(not(feature = "std"))]
            unreachable!("Path is guaranteed to contain UTF-8 or `OsStr` bytes.")
        }
    };
    wide.push(0);
    wide
}

pub(crate) fn path_is_dir(path: &Path) -> bool {
    let path = wide_path(path);
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// Registers a destructor (Stub for Windows)
pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    null_mut()
}

pub(crate) struct RawFile {
    fd: HANDLE,
    /// Stores the mapping handle for the file.
    mapping: HANDLE,
}

fn prot_win(prot: ProtFlags, is_file_mapping: bool) -> PAGE_PROTECTION_FLAGS {
    match prot.bits() {
        0 => PAGE_NOACCESS,
        1 => PAGE_READONLY,
        0b10 | 0b11 => {
            if is_file_mapping {
                PAGE_WRITECOPY
            } else {
                PAGE_READWRITE
            }
        }
        // PAGE_EXECUTE is not supported by the CreateFileMapping function:
        // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants.
        0b100 => {
            if is_file_mapping {
                PAGE_EXECUTE_READ
            } else {
                PAGE_EXECUTE
            }
        }
        0b101 => PAGE_EXECUTE_READ,
        0b110 | 0b111 => {
            if is_file_mapping {
                PAGE_EXECUTE_WRITECOPY
            } else {
                PAGE_EXECUTE_READWRITE
            }
        }
        _ => {
            panic!("Unsupported protection flags");
        }
    }
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    #[inline]
    fn file_backing(&self, backing: FileBacking) -> Result<Option<FileBacking>> {
        backing.for_mapping(self.page_size().bytes())
    }

    #[inline]
    fn page_size(&self) -> PageSize {
        let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
        unsafe {
            GetSystemInfo(info.as_mut_ptr());
            PageSize::new(info.assume_init().dwPageSize as usize).unwrap_or_default()
        }
    }

    unsafe fn create_space(
        &self,
        layout: SpaceLayout,
        prot: ProtFlags,
        init: SpaceInit,
    ) -> Result<MappedRegion<Self::Region>> {
        if matches!(init, SpaceInit::File { .. }) {
            return Err(MmapError::FileMappingUnsupported.into());
        }
        let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
        unsafe { GetSystemInfo(info.as_mut_ptr()) };
        let info = unsafe { info.assume_init() };
        let page_size = info.dwPageSize as usize;
        let padding = layout.align - page_size;
        let allocation_len = layout
            .len
            .checked_add(padding)
            .ok_or(MmapError::InvalidMappedRegionRange)?;
        // Windows requires reservation hints at allocation granularity, while
        // the image can begin at any page-aligned position inside that range.
        let hint = layout
            .addr
            .map(|addr| VmAddr::new(addr.get() & !(info.dwAllocationGranularity as usize - 1)));
        let protection = if matches!(init, SpaceInit::Zeroed) {
            prot_win(prot, false)
        } else {
            PAGE_NOACCESS
        };
        let ptr = match init {
            SpaceInit::File { .. } => unreachable!("file initialization was rejected"),
            SpaceInit::Reserve => unsafe {
                Memory::VirtualAlloc2(
                    GetCurrentProcess(),
                    hint.map_or(null(), |addr| addr.as_mut_ptr::<c_void>().cast_const()),
                    allocation_len,
                    MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                    PAGE_NOACCESS,
                    null_mut(),
                    0,
                )
            },
            SpaceInit::Zeroed => unsafe {
                Memory::VirtualAlloc(
                    hint.map_or(null(), |addr| addr.as_mut_ptr::<c_void>()),
                    allocation_len,
                    MEM_RESERVE | if padding == 0 { MEM_COMMIT } else { 0 },
                    if padding == 0 {
                        protection
                    } else {
                        PAGE_NOACCESS
                    },
                )
            },
        };
        if ptr.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::VirtualAlloc { code: err_code }.into());
        }
        let offset = layout.padding_at(VmAddr::from_ptr(ptr));
        let visible = unsafe { ptr.cast::<u8>().add(offset).cast::<c_void>() };
        if matches!(init, SpaceInit::Zeroed)
            && padding != 0
            && unsafe { Memory::VirtualAlloc(visible, layout.len, MEM_COMMIT, protection) }
                .is_null()
        {
            let code = unsafe { GetLastError() };
            unsafe { VirtualFree(ptr, 0, MEM_RELEASE) };
            return Err(MmapError::VirtualAlloc { code }.into());
        }
        // Padding stays reserved and inaccessible. Keep its ownership so later
        // placeholder splits and committed pages are released together.
        Ok(unsafe { MappedRegion::local(visible, layout.len, ptr, allocation_len, *self) })
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
        _flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()> {
        unsafe { prepare_placeholder(addr, len) }?;
        let ptr = unsafe {
            MapViewOfFile3(
                fd as HANDLE,
                GetCurrentProcess(),
                addr.as_mut_ptr::<c_void>(),
                offset as u64,
                len,
                MEM_REPLACE_PLACEHOLDER,
                prot_win(prot, true),
                null_mut(),
                0,
            )
        };
        if ptr.Value.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::MapViewOfFile3 { code: err_code }.into());
        }
        Ok(())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<()> {
        unsafe { prepare_placeholder(addr, len) }?;
        let ptr = unsafe {
            Memory::VirtualAlloc2(
                GetCurrentProcess(),
                addr.as_mut_ptr(),
                len,
                MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
                prot_win(prot, false),
                null_mut(),
                0,
            )
        };

        if ptr.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::VirtualAlloc { code: err_code }.into());
        }
        Ok(())
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        let page_size = self.page_size().bytes();
        let end = addr
            .get()
            .checked_add(len)
            .and_then(|end| end.checked_add(page_size - 1))
            .map(|end| end & !(page_size - 1))
            .ok_or(MmapError::InvalidMappedRegionRange)?;
        let mut cursor = addr.get();
        let mut first_error = None;
        while cursor < end {
            let info = query_memory(cursor)?;
            if info.AllocationBase as usize != cursor
                || !matches!(info.Type, MEM_MAPPED | MEM_PRIVATE)
            {
                return Err(MmapError::InvalidMappedRegionRange.into());
            }

            // Protection changes can split VirtualQuery regions within one
            // allocation. Find its full extent before releasing it once.
            let mut next = region_end(&info)?;
            while next < end {
                let following = query_memory(next)?;
                if following.AllocationBase != info.AllocationBase {
                    break;
                }
                next = region_end(&following)?;
            }
            if next > end {
                return Err(MmapError::InvalidMappedRegionRange.into());
            }

            let error = if info.Type == MEM_MAPPED {
                if unsafe {
                    Memory::UnmapViewOfFile(Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                        Value: cursor as _,
                    })
                } == 0
                {
                    Some(MmapError::UnmapViewOfFile {
                        code: unsafe { GetLastError() },
                    })
                } else {
                    None
                }
            } else if unsafe { VirtualFree(cursor as _, 0, MEM_RELEASE) } == 0 {
                Some(MmapError::VirtualFree {
                    code: unsafe { GetLastError() },
                })
            } else {
                None
            };
            // Keep cleaning up other allocations if one release fails.
            if first_error.is_none() {
                first_error = error;
            }
            cursor = next;
        }
        first_error.map_or(Ok(()), |error| Err(error.into()))
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        // Temporary writes to file-backed pages must retain copy-on-write semantics.
        let is_file_mapping =
            prot.contains(ProtFlags::PROT_WRITE) && query_memory(addr.get())?.Type == MEM_MAPPED;
        let mut old = MaybeUninit::uninit();
        if unsafe {
            Memory::VirtualProtect(
                addr.as_mut_ptr(),
                len,
                prot_win(prot, is_file_mapping),
                old.as_mut_ptr(),
            )
        } == 0
        {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::Mprotect { code: err_code }.into());
        }
        Ok(())
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.fd as HANDLE);
            CloseHandle(self.mapping);
        };
    }
}

impl RawFile {
    pub(crate) fn from_owned_fd(raw_fd: i32) -> Result<Self> {
        Self::from_handle(raw_fd as isize as HANDLE)
    }

    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        let wide_path = wide_path(path);

        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_EXECUTE,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                core::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err_code = unsafe { GetLastError() };
            return Err(IoError::OpenFailed {
                path: path.as_bytes().into(),
                code: err_code,
            }
            .into());
        }

        Self::from_handle(handle)
    }

    fn from_handle(handle: HANDLE) -> Result<Self> {
        let mapping = unsafe {
            CreateFileMappingW(
                handle,
                null_mut(),
                PAGE_EXECUTE_WRITECOPY,
                0 as u32,
                0 as u32,
                null(),
            )
        };
        if mapping.is_null() {
            let code = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(MmapError::CreateFileMappingW { code }.into());
        }

        Ok(Self {
            fd: handle,
            mapping,
        })
    }

    pub(crate) fn metadata(&self) -> Result<(usize, ModuleSourceId)> {
        let handle = self.fd;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(IoError::FileInfoFailed {
                code: unsafe { GetLastError() },
            }
            .into());
        }
        let file = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        let source_id =
            ModuleSourceId::file(u64::from(info.dwVolumeSerialNumber), u128::from(file));
        let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        let len = usize::try_from(size).map_err(|_| IoError::ReadBufferTooLarge)?;
        Ok((len, source_id))
    }
}

fn win_read_at(handle: HANDLE, bytes: &mut [u8], offset: usize) -> Result<usize> {
    let bytes_to_read = bytes.len().min(u32::MAX as usize) as u32;
    let ptr = bytes.as_mut_ptr();
    let mut read_count = 0u32;
    let mut overlapped = OVERLAPPED::default();
    overlapped.Anonymous.Anonymous = OVERLAPPED_0_0 {
        Offset: offset as u32,
        OffsetHigh: (offset >> 32) as u32,
    };

    let result = unsafe {
        ReadFile(
            handle,
            ptr as *mut u8,
            bytes_to_read,
            &mut read_count,
            &mut overlapped,
        )
    };

    if result == 0 {
        let err_code = unsafe { GetLastError() };
        Err(IoError::ReadFailed { code: err_code }.into())
    } else {
        Ok(read_count as usize)
    }
}

impl RawFile {
    pub(crate) fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        super::read_exact_at(buf, offset, |bytes, offset| {
            win_read_at(self.fd as HANDLE, bytes, offset)
        })
    }

    pub(crate) fn mapping_handle(&self) -> isize {
        self.mapping as isize
    }
}
