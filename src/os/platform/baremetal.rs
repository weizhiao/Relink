use crate::{
    IoError, Result,
    input::{ModuleSourceId, Path},
};

#[inline]
pub(crate) fn path_is_dir(_path: &Path) -> bool {
    false
}

pub(crate) enum RawFile {}

impl RawFile {
    pub(crate) fn from_path(_path: &Path) -> Result<Self> {
        Err(IoError::FileAccessUnsupported.into())
    }

    pub(crate) fn from_owned_fd(_raw_fd: i32) -> Result<Self> {
        Err(IoError::FileAccessUnsupported.into())
    }

    pub(crate) fn metadata(&self) -> Result<(usize, ModuleSourceId)> {
        match *self {}
    }

    pub(crate) fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<()> {
        match *self {}
    }

    pub(crate) fn mapping_handle(&self) -> isize {
        match *self {}
    }
}
