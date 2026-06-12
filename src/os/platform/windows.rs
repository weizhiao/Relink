use crate::{
    IoError, MmapError, Result,
    input::{ElfReader, Path, PathBuf},
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags},
};
use alloc::{boxed::Box, vec::Vec};
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
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GetFileSizeEx, OPEN_EXISTING, ReadFile,
    },
    System::Memory::{
        self as Memory, CreateFileMappingW, MEM_COMMIT, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE,
        MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER, MapViewOfFile3,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        VirtualFree,
    },
    System::Threading::GetCurrentProcess,
    System::{
        IO::{OVERLAPPED, OVERLAPPED_0_0},
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    },
};

#[derive(Clone, Copy)]
pub struct DefaultMmap {
    page_size: PageSize,
}

impl Default for DefaultMmap {
    fn default() -> Self {
        let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
        let page_size = unsafe {
            GetSystemInfo(info.as_mut_ptr());
            PageSize::new(info.assume_init().dwPageSize as usize).unwrap_or_default()
        };
        Self { page_size }
    }
}

#[cfg(feature = "tls")]
pub(crate) fn current_thread_id() -> usize {
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as usize }
}

/// Registers a destructor (Stub for Windows)
#[cfg(feature = "tls")]
pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

#[cfg(feature = "tls")]
pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    null_mut()
}

pub(crate) struct RawFile {
    path: PathBuf,
    fd: HANDLE,
    len: usize,
    /// Stores the mapping handle for the file.
    mapping: HANDLE,
}

fn prot_win(prot: ProtFlags, is_create_file_mapping: bool) -> PAGE_PROTECTION_FLAGS {
    match prot.bits() {
        1 => PAGE_READONLY,
        0b10 | 0b11 => {
            if is_create_file_mapping {
                PAGE_WRITECOPY
            } else {
                PAGE_READWRITE
            }
        }
        // PAGE_EXECUTE is not supported by the CreateFileMapping function:
        // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants.
        0b100 => {
            if is_create_file_mapping {
                PAGE_EXECUTE_READ
            } else {
                PAGE_EXECUTE
            }
        }
        0b101 => PAGE_EXECUTE_READ,
        0b111 => {
            if is_create_file_mapping {
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
    fn page_size(&self) -> PageSize {
        self.page_size
    }

    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>> {
        let ptr = if populate_later {
            unsafe {
                Memory::VirtualAlloc2(
                    GetCurrentProcess(),
                    addr.map_or(null(), |addr| addr.as_mut_ptr::<c_void>().cast_const()),
                    len,
                    MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                    PAGE_NOACCESS,
                    null_mut(),
                    0,
                )
            }
        } else {
            unsafe {
                Memory::VirtualAlloc(
                    addr.map_or(null(), |addr| addr.as_mut_ptr::<c_void>()),
                    len,
                    MEM_RESERVE | MEM_COMMIT,
                    prot_win(prot, false),
                )
            }
        };
        if ptr.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::VirtualAlloc { code: err_code }.into());
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
        _flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()> {
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

        if !ptr.is_null() {
            return Ok(());
        }

        let ptr = unsafe {
            Memory::VirtualAlloc(addr.as_mut_ptr(), len, MEM_COMMIT, prot_win(prot, false))
        };
        if ptr.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::VirtualAlloc { code: err_code }.into());
        }
        Ok(())
    }

    unsafe fn munmap(&self, addr: VmAddr, _len: usize) -> Result<()> {
        unsafe {
            windows_sys::Win32::System::Memory::UnmapViewOfFile(
                windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: addr.as_mut_ptr(),
                },
            )
        };
        Ok(())
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        let mut old = MaybeUninit::uninit();
        if unsafe {
            Memory::VirtualProtect(
                addr.as_mut_ptr(),
                len,
                prot_win(prot, false),
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
    pub(crate) fn from_owned_fd(path: &Path, raw_fd: i32) -> Result<Self> {
        let handle = raw_fd as isize as HANDLE;
        let mapping_handle = unsafe {
            CreateFileMappingW(
                handle,
                null_mut(),
                PAGE_EXECUTE_WRITECOPY,
                0 as u32,
                0 as u32,
                null(),
            )
        };

        if mapping_handle.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::CreateFileMappingW { code: err_code }.into());
        }

        Ok(Self {
            path: PathBuf::from(path),
            fd: handle,
            len: Self::query_len(handle)?,
            mapping: mapping_handle,
        })
    }

    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        let path_str = path.as_str();
        let mut wide_path = Vec::<u16>::with_capacity(path_str.len() + 1);
        for c in path_str.encode_utf16() {
            wide_path.push(c);
        }
        wide_path.push(0);

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
                path: path_str.into(),
                code: err_code,
            }
            .into());
        }

        let mapping_handle = unsafe {
            CreateFileMappingW(
                handle,
                null_mut(),
                PAGE_EXECUTE_WRITECOPY,
                0 as u32,
                0 as u32,
                null(),
            )
        };
        if mapping_handle.is_null() {
            let err_code = unsafe { GetLastError() };
            return Err(MmapError::CreateFileMappingW { code: err_code }.into());
        }

        Ok(Self {
            path: PathBuf::from(path),
            fd: handle,
            len: Self::query_len(handle)?,
            mapping: mapping_handle,
        })
    }

    fn query_len(handle: HANDLE) -> Result<usize> {
        let mut size = 0i64;
        if unsafe { GetFileSizeEx(handle, &mut size) } == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(IoError::SeekFailed { code: err_code }.into());
        }
        if size < 0 || size as u64 > usize::MAX as u64 {
            return Err(IoError::FailedToFillBuffer.into());
        }
        Ok(size as usize)
    }
}

fn win_read_exact_at(handle: HANDLE, mut bytes: &mut [u8], mut offset: usize) -> Result<()> {
    loop {
        if bytes.is_empty() {
            return Ok(());
        }

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
            return Err(IoError::ReadFailed { code: err_code }.into());
        } else if read_count == 0 {
            return Err(IoError::FailedToFillBuffer.into());
        }

        let n = read_count as usize;
        offset = offset.checked_add(n).ok_or_else(|| {
            IoError::ReadOutOfBounds(Box::new(crate::ReadBoundsError::new(
                offset,
                bytes.len(),
                usize::MAX,
            )))
        })?;
        bytes = &mut bytes[n..];
    }
}

pub(crate) fn virtual_free(addr: usize, len: usize) -> Result<()> {
    if unsafe { VirtualFree(addr as _, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
        let err_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(MmapError::VirtualFree { code: err_code }.into());
    }
    Ok(())
}

impl ElfReader for RawFile {
    fn len(&self) -> usize {
        self.len
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        win_read_exact_at(self.fd as HANDLE, buf, offset)
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.mapping as isize)
    }
}
