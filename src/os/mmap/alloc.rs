use crate::{
    Result,
    memory::{HostRegion, MappedRegion, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, ProtFlags},
};
use alloc::alloc::{dealloc, handle_alloc_error};
use core::{alloc::Layout, slice::from_raw_parts_mut};

/// Allocator-backed mapping for host-addressable memory.
///
/// `AllocMmap` uses the global allocator and treats the allocation address as
/// the image VM address. It is the default mapper on bare-metal targets, but it
/// can also be selected explicitly on other platforms.
#[derive(Clone, Copy, Default)]
pub struct AllocMmap;

impl AllocMmap {
    /// Creates an allocator-backed mapper.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Mmap for AllocMmap {
    type Region = HostRegion;

    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        _prot: ProtFlags,
        _populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>> {
        if let Some(addr) = addr.filter(|addr| *addr != VmAddr::null()) {
            return Ok(MappedRegion::local_alias(
                addr.as_mut_ptr::<u8>().cast(),
                len,
                *self,
            ));
        }

        let layout = unsafe { Layout::from_size_align_unchecked(len, self.page_size().bytes()) };
        let memory = unsafe { alloc::alloc::alloc(layout) };
        if memory.is_null() {
            handle_alloc_error(layout);
        }
        Ok(MappedRegion::local(memory.cast(), len, *self))
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        Ok(MappedRegion::local_alias(
            addr.as_mut_ptr::<u8>().cast(),
            len,
            *self,
        ))
    }

    unsafe fn map_file_at(
        &self,
        _addr: VmAddr,
        _len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
        _offset: usize,
        _fd: isize,
    ) -> Result<()> {
        Ok(())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        _prot: ProtFlags,
        _flags: MapFlags,
    ) -> Result<()> {
        unsafe { from_raw_parts_mut(addr.as_mut_ptr::<u8>(), len) }.fill(0);
        Ok(())
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        unsafe {
            dealloc(
                addr.as_mut_ptr(),
                Layout::from_size_align_unchecked(len, self.page_size().bytes()),
            )
        };
        Ok(())
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_hint_allocates_memory() {
        let mapper = AllocMmap::new();
        let region = unsafe {
            mapper
                .create_space(
                    Some(VmAddr::null()),
                    mapper.page_size().bytes(),
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    false,
                )
                .unwrap()
        };

        assert_ne!(region.addr(), VmAddr::null());
    }
}
