use crate::{
    IoError, Result,
    input::{ElfReader, ModuleSourceId, Path},
};
use core::ffi::c_void;

#[inline]
pub(crate) fn path_is_dir(_path: &Path) -> bool {
    false
}

pub(crate) fn current_thread_id() -> usize {
    0
}

pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    core::ptr::null_mut()
}

pub(crate) enum RawFile {}

impl RawFile {
    pub(crate) fn from_path(_path: &Path) -> Result<Self> {
        Err(IoError::FileAccessUnsupported.into())
    }

    pub(crate) fn from_owned_fd(_path: &Path, _raw_fd: i32) -> Result<Self> {
        Err(IoError::FileAccessUnsupported.into())
    }
}

impl ElfReader for RawFile {
    fn path(&self) -> &Path {
        match *self {}
    }

    fn len(&self) -> usize {
        match *self {}
    }

    fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<()> {
        match *self {}
    }

    fn source_id(&self) -> ModuleSourceId {
        match *self {}
    }

    fn as_fd(&self) -> Option<isize> {
        match *self {}
    }
}
