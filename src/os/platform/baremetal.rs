use crate::{
    Result,
    input::{ElfReader, Path},
    os::{HostRegion, MadviseAdvice, MapFlags, MappedRegion, Mmap, ProtFlags, VmAddr},
};
use alloc::alloc::{dealloc, handle_alloc_error};
#[cfg(feature = "tls")]
use core::ffi::c_void;
use core::{alloc::Layout, slice::from_raw_parts_mut};

/// An implementation of Mmap trait
#[derive(Clone, Copy, Default)]
pub struct DefaultMmap;

#[cfg(feature = "tls")]
pub(crate) fn current_thread_id() -> usize {
    0
}

#[cfg(feature = "tls")]
pub(crate) unsafe fn register_thread_destructor(
    _destructor: unsafe extern "C" fn(*mut c_void),
    _value: *mut c_void,
) {
}

#[cfg(feature = "tls")]
pub(crate) unsafe fn get_thread_local_ptr() -> *mut c_void {
    core::ptr::null_mut()
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        _prot: ProtFlags,
        _populate_later: bool,
    ) -> crate::Result<MappedRegion<Self::Region>> {
        if let Some(addr) = addr {
            let ptr = addr.as_mut_ptr::<u8>();
            Ok(MappedRegion::local_alias(ptr as _, len, *self))
        } else {
            let layout =
                unsafe { Layout::from_size_align_unchecked(len, self.page_size().bytes()) };
            let memory = unsafe { alloc::alloc::alloc(layout) };
            if memory.is_null() {
                handle_alloc_error(layout);
            }
            // use this set prot to test no_mmap
            //libc::mprotect(memory as _, len, crate::mmap::ProtFlags::all().bits());
            Ok(MappedRegion::local(memory as _, len, *self))
        }
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        Ok(MappedRegion::local_alias(addr.as_mut_ptr(), len, *self))
    }

    unsafe fn map_file_at(
        &self,
        _addr: VmAddr,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
        _offset: usize,
        _fd: isize,
    ) -> crate::Result<()> {
        Ok(())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
    ) -> crate::Result<()> {
        let ptr = addr.as_mut_ptr::<u8>();
        let dest = unsafe { from_raw_parts_mut(ptr, len) };
        dest.fill(0);
        Ok(())
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> crate::Result<()> {
        unsafe {
            dealloc(
                addr.as_mut_ptr(),
                Layout::from_size_align_unchecked(len, self.page_size().bytes()),
            )
        };
        Ok(())
    }

    unsafe fn madvise(
        &self,
        _addr: VmAddr,
        _len: usize,
        _behavior: MadviseAdvice,
    ) -> crate::Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> crate::Result<()> {
        Ok(())
    }
}

pub(crate) struct RawFile;

impl RawFile {
    pub(crate) fn from_path(_path: &Path) -> Result<Self> {
        unimplemented!()
    }

    pub(crate) fn from_owned_fd(_path: &Path, _raw_fd: i32) -> Result<Self> {
        todo!()
    }
}

impl ElfReader for RawFile {
    fn path(&self) -> &Path {
        todo!()
    }

    fn len(&self) -> usize {
        todo!()
    }

    fn read(&mut self, _buf: &mut [u8], _offset: usize) -> Result<()> {
        todo!()
    }

    fn as_fd(&self) -> Option<isize> {
        todo!()
    }
}
