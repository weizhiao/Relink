use crate::{
    ByteRepr, MmapError, Result,
    memory::{HostRegion, ImageMemory, MappedRegion, MappedView, RegionAccess, VmAddr, VmOffset},
    os::ProtFlags,
};
use core::{
    fmt::{self, Debug, Display},
    ops::Range,
    ptr::NonNull,
};

/// A contiguous ELF mapping at an offset relative to the image base.
pub struct ElfSegments<R: RegionAccess = HostRegion> {
    base: VmAddr,
    region: MappedRegion<R>,
    range: Range<VmAddr>,
}

impl<R: RegionAccess> Debug for ElfSegments<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<R: RegionAccess> Display for ElfSegments<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "base: {}, range: {}..{} (+{} len 0x{:x})",
            self.base,
            self.range.start,
            self.range.end,
            self.range.start.wrapping_offset_from(self.base),
            self.region.len()
        )
    }
}

impl<R: RegionAccess> ElfSegments<R> {
    #[inline]
    pub(crate) fn contains_range(&self, addr: VmAddr, len: usize) -> bool {
        self.range.start <= addr
            && addr
                .checked_add(VmOffset::new(len))
                .is_some_and(|end| end <= self.range.end)
    }

    #[inline]
    fn region_offset(&self, addr: VmAddr) -> usize {
        addr.wrapping_offset_from(self.range.start).get()
    }

    /// Describes a contiguous mapped region and the load base used for ELF offsets.
    pub fn new(region: MappedRegion<R>, base: VmAddr) -> Self {
        let start = region.addr();
        let len = region.len();
        assert!(
            start.wrapping_offset_from(base).checked_add(len).is_some(),
            "ELF mapped range overflowed"
        );
        let end = start
            .checked_add(VmOffset::new(len))
            .expect("ELF mapped address range overflowed");
        Self {
            base,
            region,
            range: start..end,
        }
    }

    /// Returns whether the mapping contains `addr`.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        self.range.contains(&addr)
    }

    /// Returns the half-open range of runtime addresses covered by this mapping.
    #[inline]
    pub const fn range(&self) -> Range<VmAddr> {
        self.range.start..self.range.end
    }

    #[inline]
    pub(crate) fn read_view<T: ByteRepr + 'static>(
        &self,
        offset: VmOffset,
        byte_len: usize,
    ) -> Option<MappedView<T>> {
        let addr = self.base() + offset;
        if !self.contains_range(addr, byte_len) {
            return None;
        }
        let region_offset = self.region_offset(addr);
        self.region.read_view(region_offset, byte_len)
    }

    /// Reads typed entries from `offset` to the end of its mapped range.
    ///
    /// This is useful for ELF tables such as `DT_SYMTAB`, whose dynamic tags
    /// provide a base address but no logical entry count. The returned view is
    /// bounded by mapped memory; callers must still obtain valid indices from
    /// the table's associated metadata.
    pub(crate) fn read_tail_view<T: ByteRepr + 'static>(
        &self,
        offset: VmOffset,
    ) -> Option<MappedView<T>> {
        let entry_size = core::mem::size_of::<T>();
        if entry_size == 0 {
            return None;
        }

        let addr = self.base + offset;
        let remaining = self.range.end.checked_offset_from(addr)?.get();
        let byte_len = remaining - remaining % entry_size;
        if byte_len == 0 {
            return None;
        }
        self.read_view(offset, byte_len)
    }

    #[inline]
    pub(crate) fn zero_bytes(&self, addr: VmAddr, len: usize) -> Result<()> {
        debug_assert!(self.contains_range(addr, len));
        unsafe { self.region.zero_bytes(self.region_offset(addr), len) }
    }

    #[inline]
    pub(crate) fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        debug_assert!(self.contains_range(addr, len));
        unsafe { self.region.mprotect(self.region_offset(addr), len, prot) }
    }

    /// Returns the base address of the mapped memory as a raw integer.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.base
    }
}

impl<R: RegionAccess> ImageMemory for ElfSegments<R> {
    #[inline]
    fn base(&self) -> VmAddr {
        self.base()
    }

    fn range_at(&self, addr: VmAddr) -> Option<Range<VmAddr>> {
        self.range.contains(&addr).then(|| self.range())
    }

    fn visit_ranges(&self, visit: &mut dyn FnMut(Range<VmAddr>)) {
        if !self.range.is_empty() {
            visit(self.range());
        }
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        self.host_ptr_range(addr, 1)
    }

    #[inline]
    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        if !self.contains_range(addr, len.max(1)) {
            return None;
        }
        unsafe { self.region.host_ptr(self.region_offset(addr)) }
    }

    #[inline]
    unsafe fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        if !self.contains_range(addr, dst.len()) {
            return Err(MmapError::InvalidMappedRegionRange.into());
        }
        unsafe { self.region.read_bytes(self.region_offset(addr), dst) }
    }

    #[inline]
    unsafe fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        if !self.contains_range(addr, src.len()) {
            return Err(MmapError::InvalidMappedRegionRange.into());
        }
        unsafe { self.region.write_bytes(self.region_offset(addr), src) }
    }
}
