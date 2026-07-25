use core::ptr::{NonNull, copy_nonoverlapping, write_bytes};

use crate::{
    MmapError, Result,
    memory::{MappedRegion, RegionAccess, VmAddr},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags},
};

/// A fixed-capacity mapping backed by caller-owned, host-accessible memory.
///
/// `FixedMmap` is useful on bare-metal and Harvard-architecture targets where
/// an image has one address for execution and another address for data access.
/// It does not allocate or release memory and supports one fixed VM range.
#[derive(Clone, Copy, Debug)]
pub struct FixedMmap {
    addr: VmAddr,
    host: VmAddr,
    len: usize,
}

impl FixedMmap {
    /// Creates a mapper over a caller-owned fixed memory range.
    ///
    /// `addr` is the address visible to the loaded image, while `host` is the
    /// address Relink uses to read and write the same physical storage.
    ///
    /// # Safety
    ///
    /// - `host..host + len` must remain valid and exclusively owned by this
    ///   mapper while any returned mapping exists.
    /// - `addr` and `host` must refer to the same storage.
    /// - Both addresses must be aligned to [`PageSize::Base`].
    /// - The caller must prevent overlapping live mappings over the same range.
    #[inline]
    pub const unsafe fn new(addr: VmAddr, host: VmAddr, len: usize) -> Self {
        Self { addr, host, len }
    }

    #[inline]
    fn region(&self, addr: VmAddr, len: usize) -> Result<FixedRegion> {
        let offset = addr
            .get()
            .checked_sub(self.addr.get())
            .ok_or(MmapError::InvalidMappedRegionRange)?;
        let end = offset
            .checked_add(len)
            .ok_or(MmapError::InvalidMappedRegionRange)?;
        if end > self.len {
            return Err(MmapError::InvalidMappedRegionRange.into());
        }

        Ok(FixedRegion {
            addr,
            host: VmAddr::new(self.host.get() + offset),
            len,
        })
    }

    #[inline]
    fn offset(&self, addr: VmAddr, len: usize) -> Result<usize> {
        self.region(addr, len)
            .map(|region| region.host.get() - self.host.get())
    }
}

/// One mapped view produced by [`FixedMmap`].
pub struct FixedRegion {
    addr: VmAddr,
    host: VmAddr,
    len: usize,
}

impl FixedRegion {
    #[inline]
    unsafe fn host_ptr(&self, offset: usize) -> *mut u8 {
        unsafe { self.host.as_mut_ptr::<u8>().add(offset) }
    }
}

impl RegionAccess for FixedRegion {
    #[inline]
    fn addr(&self) -> VmAddr {
        self.addr
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        unsafe { copy_nonoverlapping(self.host_ptr(offset), dst.as_mut_ptr(), dst.len()) };
        Ok(())
    }

    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
        unsafe { copy_nonoverlapping(src.as_ptr(), self.host_ptr(offset), src.len()) };
        Ok(())
    }

    unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
        unsafe { write_bytes(self.host_ptr(offset), 0, len) };
        Ok(())
    }

    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        Some(unsafe { core::slice::from_raw_parts(self.host_ptr(offset), len) })
    }

    unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>> {
        NonNull::new(unsafe { self.host_ptr(offset) })
    }

    unsafe fn madvise(&self, _offset: usize, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _offset: usize, _len: usize, _prot: ProtFlags) -> Result<()> {
        Ok(())
    }
}

impl Mmap for FixedMmap {
    type Region = FixedRegion;

    #[inline]
    fn page_size(&self) -> PageSize {
        PageSize::Base
    }

    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        _prot: ProtFlags,
        _populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>> {
        let addr = addr.unwrap_or(self.addr);
        if addr != self.addr {
            return Err(MmapError::InvalidMappedRegionRange.into());
        }
        let region = self.region(addr, len)?;
        unsafe { write_bytes(region.host.as_mut_ptr::<u8>(), 0, len) };
        Ok(MappedRegion::new(region))
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        self.region(addr, len).map(MappedRegion::new)
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
        let offset = self.offset(addr, len)?;
        unsafe { write_bytes(self.host.as_mut_ptr::<u8>().add(offset), 0, len) };
        Ok(())
    }

    unsafe fn munmap(&self, _addr: VmAddr, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn madvise(&self, _addr: VmAddr, _len: usize, _behavior: MadviseAdvice) -> Result<()> {
        Ok(())
    }

    unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
        Ok(())
    }
}
