use crate::{
    ElfReader, Error, Result, io_error,
    mmap::{MapFlags, Mmap, ProtFlags},
};
use alloc::{ffi::CString, format, vec::Vec};
use core::{
    ffi::{CStr, c_void},
    mem::MaybeUninit,
    ptr::{NonNull, null, null_mut},
    str::FromStr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GENERIC_EXECUTE, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_READ, OPEN_EXISTING, ReadFile,
        SetFilePointerEx,
    },
    System::Memory::{
        self as Memory, CreateFileMappingW, MEM_COMMIT, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE,
        MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER, MapViewOfFile3,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        VirtualFree,
    },
    System::Threading::GetCurrentProcess,
};

pub struct DefaultMmap;

pub(crate) fn current_thread_id() -> usize {
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as usize }
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
    name: CString,
    fd: HANDLE,
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
    unsafe fn mmap(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        _flags: MapFlags,
        offset: usize,
        fd: Option<isize>,
        need_copy: &mut bool,
    ) -> Result<NonNull<c_void>> {
        let ptr = if let Some(fd) = fd {
            debug_assert!(addr.is_some(), "Address must be specified.");
            let addr = addr.unwrap();
            let handle = fd as HANDLE;
            let desired_addr = addr as *mut c_void;

            let ptr = unsafe {
                MapViewOfFile3(
                    handle,
                    GetCurrentProcess(),
                    desired_addr,
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
                return Err(Error::Mmap {
                    msg: format!("MapViewOfFile3 failed with error: {}", err_code).into(),
                });
            }
            ptr.Value
        } else {
            *need_copy = true;
            debug_assert!(addr.is_some(), "Address must be specified.");
            let addr = addr.unwrap();
            addr as _
        };
        Ok(NonNull::new(ptr).unwrap())
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<NonNull<c_void>> {
        // TODO： Change implementation using VirtualFree + VirtualAlloc
        let ptr =
            unsafe { Memory::VirtualAlloc(addr as _, len, MEM_COMMIT, prot_win(prot, false)) };
        Ok(NonNull::new(ptr).unwrap())
    }

    unsafe fn munmap(addr: NonNull<c_void>, _len: usize) -> Result<()> {
        unsafe {
            windows_sys::Win32::System::Memory::UnmapViewOfFile(
                windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: addr.as_ptr(),
                },
            )
        };
        Ok(())
    }

    unsafe fn mprotect(addr: NonNull<c_void>, len: usize, prot: ProtFlags) -> Result<()> {
        let mut old = MaybeUninit::uninit();
        if unsafe {
            Memory::VirtualProtect(addr.as_ptr(), len, prot_win(prot, false), old.as_mut_ptr())
        } == 0
        {
            let err_code = unsafe { GetLastError() };
            return Err(Error::MmapError {
                msg: format!("mprotect error! error code: {}", err_code),
            });
        }
        Ok(())
    }

    unsafe fn mmap_reserve(
        addr: Option<usize>,
        len: usize,
        use_file: bool,
    ) -> Result<NonNull<c_void>> {
        let ptr = if use_file {
            if let Some(addr) = addr {
                unsafe {
                    Memory::VirtualAlloc2(
                        null_mut(),
                        addr as _,
                        len,
                        MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                        PAGE_NOACCESS,
                        null_mut(),
                        0,
                    )
                }
            } else {
                unsafe {
                    Memory::VirtualAlloc2(
                        null_mut(),
                        null_mut(),
                        len,
                        MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                        PAGE_NOACCESS,
                        null_mut(),
                        0,
                    )
                }
            }
        } else {
            unsafe {
                let ptr = Memory::VirtualAlloc(
                    null(),
                    len,
                    MEM_RESERVE | MEM_COMMIT,
                    prot_win(ProtFlags::PROT_WRITE, false),
                );
                ptr
            }
        };
        if ptr.is_null() {
            return Err(Error::MmapError {
                msg: "VirtualAlloc failed".into(),
            });
        }
        Ok(NonNull::new(ptr).unwrap())
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
    pub(crate) fn from_owned_fd(_path: &str, _raw_fd: i32) -> Self {
        todo!()
    }

    pub(crate) fn from_path(path: &str) -> Result<Self> {
        let mut wide_path = Vec::<u16>::with_capacity(path.len() + 1);
        for c in path.encode_utf16() {
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
            return Err(io_error(&format!(
                "CreateFileW failed with error: {}",
                err_code
            )));
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
        if mapping_handle == INVALID_HANDLE_VALUE {
            let err_code = unsafe { GetLastError() };
            return Err(Error::MmapError {
                msg: format!("CreateFileMappingW failed with error: {}", err_code),
            });
        }

        Ok(Self {
            name: CString::from_str(path).unwrap(),
            fd: handle,
            mapping: mapping_handle,
        })
    }
}

fn win_seek(handle: HANDLE, offset: usize) -> Result<()> {
    let distance = offset as i64;
    let mut new_pos = 0i64;

    let res = unsafe { SetFilePointerEx(handle, distance, &mut new_pos, FILE_BEGIN) };

    if res == 0 || new_pos as usize != offset {
        let err_code = unsafe { GetLastError() };
        return Err(io_error(&format!(
            "SetFilePointerEx failed with error: {}",
            err_code
        )));
    }
    Ok(())
}

fn win_read_exact(handle: HANDLE, mut bytes: &mut [u8]) -> Result<()> {
    loop {
        if bytes.is_empty() {
            return Ok(());
        }

        let bytes_to_read = bytes.len().min(u32::MAX as usize) as u32;
        let ptr = bytes.as_mut_ptr();
        let mut read_count = 0u32;

        let result = unsafe {
            ReadFile(
                handle,
                ptr as *mut u8,
                bytes_to_read,
                &mut read_count,
                null_mut(),
            )
        };

        if result == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(io_error(&format!(
                "ReadFile failed with error: {}",
                err_code
            )));
        } else if read_count == 0 {
            return Err(io_error("failed to fill buffer"));
        }

        let n = read_count as usize;
        bytes = &mut bytes[n..];
    }
}

pub(crate) fn virtual_free(addr: usize, len: usize) -> Result<()> {
    if unsafe { VirtualFree(addr as _, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
        let err_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(crate::Error::MmapError {
            msg: alloc::format!("VirtualFree failed with error: {}", err_code),
        });
    }
    Ok(())
}

impl ElfReader for RawFile {
    fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
        win_seek(self.fd as HANDLE, offset)?;
        win_read_exact(self.fd as HANDLE, buf)?;
        Ok(())
    }

    fn file_name(&self) -> &CStr {
        &self.name
    }

    fn as_fd(&self) -> Option<isize> {
        Some(self.mapping as isize)
    }
}
