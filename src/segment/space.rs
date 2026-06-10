use crate::{
    ByteRepr, Result,
    os::{
        HostRegion, ImageMemory, MappedRegion, MappedView, ProtFlags, RegionAccess, VmAddr,
        VmOffset,
    },
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, ptr::NonNull};

#[derive(Clone, Copy)]
struct MappedRange {
    offset: VmOffset,
    len: usize,
}

impl MappedRange {
    #[inline]
    const fn new(offset: VmOffset, len: usize) -> Self {
        Self { offset, len }
    }

    #[inline]
    fn contains_offset_range(self, offset: usize, len: usize) -> bool {
        offset
            .checked_sub(self.offset.get())
            .and_then(|delta| delta.checked_add(len))
            .is_some_and(|end| end <= self.len)
    }

    #[inline]
    fn end(self) -> VmOffset {
        self.offset
            .checked_add(self.len)
            .expect("ELF mapped range overflowed")
    }
}

/// The mapped memory of an ELF object.
///
/// All mapped bytes are backed by one region. `ranges` records the parts of
/// the module-runtime address space owned by this image.
pub struct ElfSegments<R: RegionAccess = HostRegion> {
    base: VmAddr,
    region: MappedRegion<R>,
    ranges: Box<[MappedRange]>,
}

impl<R: RegionAccess> Debug for ElfSegments<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ranges = self
            .ranges
            .iter()
            .map(|range| (range.offset, range.len))
            .collect::<Vec<_>>();
        f.debug_struct("ElfSegments")
            .field("base", &format_args!("{}", self.base()))
            .field("ranges", &ranges)
            .field("contiguous", &self.is_contiguous_mapping())
            .finish()
    }
}

impl<R: RegionAccess> ElfSegments<R> {
    fn normalize_ranges(mut ranges: Vec<MappedRange>) -> Box<[MappedRange]> {
        ranges.sort_by_key(|range| (range.offset, range.len));

        let mut merged = Vec::with_capacity(ranges.len());
        for range in ranges {
            let range_end = range.end();
            let Some(previous_idx) = merged.len().checked_sub(1) else {
                merged.push(range);
                continue;
            };

            let previous = merged[previous_idx];
            let previous_end = previous.end();
            assert!(
                previous_end <= range.offset,
                "ELF mapped ranges must not overlap",
            );

            if previous_end == range.offset {
                merged[previous_idx].len = range_end
                    .checked_offset_from(previous.offset)
                    .expect("ELF mapped range overflowed")
                    .get();
            } else {
                merged.push(range);
            }
        }

        merged.into_boxed_slice()
    }

    #[inline]
    pub(crate) fn contains_range(&self, addr: VmAddr, len: usize) -> bool {
        let Some(offset) = addr.checked_offset_from(self.base) else {
            return false;
        };
        let idx = self.ranges.partition_point(|range| range.offset <= offset);
        idx > 0 && self.ranges[idx - 1].contains_offset_range(offset.get(), len)
    }

    #[inline]
    fn range_base(&self, range: MappedRange) -> VmAddr {
        self.base + range.offset
    }

    #[inline]
    fn region_offset(&self, addr: VmAddr) -> usize {
        addr.wrapping_offset_from(self.region.addr()).get()
    }

    /// Create a new contiguous [`ElfSegments`] instance whose mapped bytes begin
    /// at the module-relative `offset`.
    pub(crate) fn new(region: MappedRegion<R>, base: VmAddr, offset: VmOffset) -> Self {
        let len = region.len();
        let range = MappedRange::new(offset, len);
        let ranges = Box::new([range]);
        Self {
            base,
            region,
            ranges,
        }
    }

    /// Creates an [`ElfSegments`] instance from mapped ranges inside one shared
    /// backing region.
    pub(crate) fn from_ranges(
        region: MappedRegion<R>,
        base: VmAddr,
        ranges: Vec<(usize, usize)>,
    ) -> Self {
        let ranges = ranges
            .into_iter()
            .map(|(offset, len)| MappedRange::new(VmOffset::new(offset), len))
            .collect::<Vec<_>>();
        let ranges = Self::normalize_ranges(ranges);

        for range in ranges.iter().copied() {
            let region_offset = base
                .checked_add(range.offset)
                .and_then(|addr| addr.checked_offset_from(region.addr()))
                .expect("ELF mapped range precedes its backing region");
            assert!(
                region_offset
                    .checked_add(range.len)
                    .is_some_and(|end| end.get() <= region.len()),
                "ELF mapped range exceeds its backing region",
            );
        }

        Self {
            base,
            region,
            ranges,
        }
    }

    /// Rebinds the module base address while preserving the existing range layout.
    #[inline]
    pub(crate) fn set_base(&mut self, base: VmAddr) {
        self.base = base;
    }

    /// Returns the mapped region, when this object owns one.
    #[inline]
    #[cfg(windows)]
    pub(crate) fn primary_region(&self) -> Option<(*mut core::ffi::c_void, usize)> {
        Some((self.region.addr().get() as *mut _, self.region.len()))
    }

    /// Returns whether no ranges are mapped.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the lowest runtime address covered by this image's mapped ranges.
    #[inline]
    pub fn mapped_base(&self) -> VmAddr {
        self.ranges
            .first()
            .copied()
            .map(|range| self.range_base(range))
            .unwrap_or_else(VmAddr::null)
    }

    /// Returns the length of the bounding runtime span covered by mapped ranges.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        let Some((first, last)) = self
            .ranges
            .first()
            .copied()
            .zip(self.ranges.last().copied())
        else {
            return 0;
        };
        last.end()
            .checked_offset_from(first.offset)
            .expect("ELF mapped range end precedes its start")
            .get()
    }

    /// Returns whether `addr` is inside one of this image's mapped ranges.
    #[inline]
    pub fn contains_addr(&self, addr: VmAddr) -> bool {
        self.ranges.iter().copied().any(|range| {
            addr.checked_offset_from(self.range_base(range))
                .is_some_and(|offset| offset.get() < range.len)
        })
    }

    /// Returns whether the mapped memory is one contiguous span with no gaps.
    #[inline]
    pub fn is_contiguous_mapping(&self) -> bool {
        self.ranges.len() <= 1
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

    #[inline]
    pub(crate) fn borrowed_ptr<T: ByteRepr + 'static>(
        &self,
        offset: VmOffset,
        byte_len: usize,
    ) -> Option<NonNull<T>> {
        self.read_view::<T>(offset, byte_len)
            .and_then(|view| view.as_slice().first().map(NonNull::from))
    }

    /// Translates an image VM address into a host-accessible pointer.
    ///
    /// Returns `None` when the address is outside this image or the backing
    /// mapping cannot be borrowed directly by the current process.
    #[inline]
    pub fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        debug_assert!(self.contains_range(addr, 1));
        unsafe { self.region.host_ptr(self.region_offset(addr)) }
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        debug_assert!(self.contains_range(addr, len));
        unsafe { self.region.host_ptr(self.region_offset(addr)) }
    }

    #[inline]
    pub(crate) fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        debug_assert!(self.contains_range(addr, dst.len()));
        unsafe { self.region.read_bytes(self.region_offset(addr), dst) }
    }

    #[inline]
    pub(crate) fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        debug_assert!(self.contains_range(addr, src.len()));
        unsafe { self.region.write_bytes(self.region_offset(addr), src) }
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

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        self.host_ptr(addr)
    }

    #[inline]
    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        self.host_ptr_range(addr, len)
    }

    #[inline]
    fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        self.read_bytes(addr, dst)
    }

    #[inline]
    fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        self.write_bytes(addr, src)
    }
}
