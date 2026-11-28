use crate::{
    ByteRepr, Result,
    memory::{HostRegion, ImageMemory, MappedRegion, MappedView, RegionAccess, VmAddr, VmOffset},
    os::ProtFlags,
};
use core::{
    fmt::{self, Debug, Display},
    ops::Range,
    ptr::NonNull,
};

/// A mapped module-relative range owned by an ELF image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedRange {
    /// Range start, relative to the image base address.
    pub offset: VmOffset,
    /// Range length in bytes.
    pub len: usize,
}

impl MappedRange {
    #[inline]
    const fn new(offset: VmOffset, len: usize) -> Self {
        assert!(
            offset.get().checked_add(len).is_some(),
            "ELF mapped range overflowed",
        );
        Self { offset, len }
    }

    #[inline]
    fn end(self) -> VmOffset {
        VmOffset::new(self.offset.get() + self.len)
    }
}

/// A contiguous ELF mapping at an offset relative to the image base.
pub struct ElfSegments<R: RegionAccess = HostRegion> {
    base: VmAddr,
    region: MappedRegion<R>,
    range: MappedRange,
}

impl<R: RegionAccess> Debug for ElfSegments<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<R: RegionAccess> Display for ElfSegments<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mapped = self.address_range();
        write!(
            f,
            "base: {}, range: {}..{} (+{} len 0x{:x})",
            self.base, mapped.start, mapped.end, self.range.offset, self.range.len
        )
    }
}

impl<R: RegionAccess> ElfSegments<R> {
    #[inline]
    fn address_range(&self) -> Range<VmAddr> {
        self.base + self.range.offset..self.base + self.range.end()
    }

    #[inline]
    pub(crate) fn contains_range(&self, addr: VmAddr, len: usize) -> bool {
        addr.checked_offset_from(self.base + self.range.offset)
            .and_then(|offset| offset.checked_add(len))
            .is_some_and(|end| end.get() <= self.range.len)
    }

    #[inline]
    fn region_offset(&self, addr: VmAddr) -> usize {
        addr.wrapping_offset_from(self.region.addr()).get()
    }

    /// Create a new contiguous [`ElfSegments`] instance whose mapped bytes begin
    /// at the module-relative `offset`.
    pub fn new(region: MappedRegion<R>, base: VmAddr, offset: VmOffset) -> Self {
        let range = MappedRange::new(offset, region.len());
        Self {
            base,
            region,
            range,
        }
    }

    /// Returns whether the mapping contains `addr`.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        self.contains_range(addr, 1)
    }

    /// Returns the offset and byte length of this mapping relative to the image base.
    #[inline]
    pub const fn range(&self) -> MappedRange {
        self.range
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

        let relative = offset.checked_offset_from(self.range.offset)?;
        let remaining = self.range.len.checked_sub(relative.get())?;
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
        let mapped = self.address_range();
        mapped.contains(&addr).then_some(mapped)
    }

    fn visit_ranges(&self, visit: &mut dyn FnMut(Range<VmAddr>)) {
        visit(self.address_range());
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        self.host_ptr_range(addr, 1)
    }

    #[inline]
    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        debug_assert!(self.contains_range(addr, len));
        unsafe { self.region.host_ptr(self.region_offset(addr)) }
    }

    #[inline]
    fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        debug_assert!(self.contains_range(addr, dst.len()));
        unsafe { self.region.read_bytes(self.region_offset(addr), dst) }
    }

    #[inline]
    fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        debug_assert!(self.contains_range(addr, src.len()));
        unsafe { self.region.write_bytes(self.region_offset(addr), src) }
    }
}
