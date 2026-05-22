use crate::{
    ByteRepr, Result,
    os::{HostRegion, MappedRegion, MappedView, RegionAccess, VmAddr},
    relocation::RelocValue,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt::Debug,
    mem::{MaybeUninit, size_of},
    ptr::NonNull,
};

#[derive(Clone, Copy)]
struct MappedRange {
    offset: usize,
    len: usize,
}

impl MappedRange {
    #[inline]
    const fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }

    #[inline]
    fn contains_offset_range(self, offset: usize, len: usize) -> bool {
        offset
            .checked_sub(self.offset)
            .and_then(|delta| delta.checked_add(len))
            .is_some_and(|end| end <= self.len)
    }

    #[inline]
    fn end(self) -> usize {
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
    base: usize,
    region: MappedRegion<R>,
    ranges: Box<[MappedRange]>,
    contiguous: bool,
}

impl<R: RegionAccess> Debug for ElfSegments<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ranges = self
            .ranges
            .iter()
            .map(|range| (range.offset, range.len))
            .collect::<Vec<_>>();
        f.debug_struct("ElfSegments")
            .field("base", &format_args!("0x{:x}", self.base()))
            .field("ranges", &ranges)
            .field("contiguous", &self.contiguous)
            .finish()
    }
}

impl<R: RegionAccess> ElfSegments<R> {
    fn normalize_ranges(mut ranges: Vec<MappedRange>) -> (Box<[MappedRange]>, bool) {
        ranges.sort_by_key(|range| (range.offset, range.len));
        for pair in ranges.windows(2) {
            let previous = pair[0];
            let next = pair[1];
            assert!(
                previous.end() <= next.offset,
                "ELF mapped ranges must not overlap",
            );
        }

        let contiguous = ranges
            .windows(2)
            .all(|pair| pair[0].end() == pair[1].offset);
        (ranges.into_boxed_slice(), contiguous)
    }

    #[inline]
    fn first_range(&self) -> Option<MappedRange> {
        self.ranges.first().copied()
    }

    #[inline]
    fn last_range(&self) -> Option<MappedRange> {
        self.ranges.last().copied()
    }

    #[inline]
    fn find_range(&self, addr: VmAddr, len: usize) -> Option<MappedRange> {
        let offset = addr.get().checked_sub(self.base)?;
        let idx = self
            .ranges
            .partition_point(|range| range.offset <= offset)
            .checked_sub(1)?;
        let range = self.ranges[idx];
        range.contains_offset_range(offset, len).then_some(range)
    }

    #[inline]
    fn contains_range(&self, addr: VmAddr, len: usize) -> bool {
        self.find_range(addr, len).is_some()
    }

    #[inline]
    fn range_base(&self, range: MappedRange) -> usize {
        self.base.saturating_add(range.offset)
    }

    #[inline]
    fn region_offset(&self, addr: VmAddr) -> usize {
        addr.get().wrapping_sub(self.region.addr().get())
    }

    /// Create a new contiguous [`ElfSegments`] instance whose mapped bytes begin
    /// at the module-relative `offset`.
    pub(crate) fn new(region: MappedRegion<R>, base: usize, offset: usize) -> Self {
        let len = region.len();
        let range = MappedRange::new(offset, len);
        let (ranges, contiguous) = Self::normalize_ranges(alloc::vec![range]);
        Self {
            base,
            region,
            ranges,
            contiguous,
        }
    }

    /// Creates an [`ElfSegments`] instance from mapped ranges inside one shared
    /// backing region.
    pub(crate) fn from_ranges(
        region: MappedRegion<R>,
        base: usize,
        ranges: Vec<(usize, usize)>,
    ) -> Self {
        let ranges = ranges
            .into_iter()
            .map(|(offset, len)| MappedRange::new(offset, len))
            .collect::<Vec<_>>();
        let (ranges, contiguous) = Self::normalize_ranges(ranges);

        for range in ranges.iter().copied() {
            let region_offset = base
                .checked_add(range.offset)
                .and_then(|addr| addr.checked_sub(region.addr().get()))
                .expect("ELF mapped range precedes its backing region");
            assert!(
                region_offset
                    .checked_add(range.len)
                    .is_some_and(|end| end <= region.len()),
                "ELF mapped range exceeds its backing region",
            );
        }

        Self {
            base,
            region,
            ranges,
            contiguous,
        }
    }

    /// Rebinds the module base address while preserving the existing range layout.
    #[inline]
    pub(crate) fn set_base(&mut self, base: usize) {
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
    pub fn mapped_base(&self) -> usize {
        self.first_range()
            .map(|range| self.range_base(range))
            .unwrap_or(0)
    }

    /// Returns the length of the bounding runtime span covered by mapped ranges.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        let Some((first, last)) = self.first_range().zip(self.last_range()) else {
            return 0;
        };
        self.range_base(last)
            .saturating_add(last.len)
            .saturating_sub(self.range_base(first))
    }

    /// Returns whether `addr` is inside one of this image's mapped ranges.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        if self.contiguous {
            let Some(first) = self.first_range() else {
                return false;
            };
            let start = self.base.saturating_add(first.offset);
            let len = self.mapped_len();
            return addr.checked_sub(start).is_some_and(|offset| offset < len);
        }

        self.ranges.iter().copied().any(|range| {
            addr.checked_sub(self.range_base(range))
                .is_some_and(|offset| offset < range.len)
        })
    }

    /// Returns whether the mapped memory is one contiguous span with no gaps.
    #[inline]
    pub fn is_contiguous_mapping(&self) -> bool {
        self.contiguous
    }

    #[inline]
    pub(crate) fn read_view<T: ByteRepr + 'static>(
        &self,
        offset: usize,
        byte_len: usize,
    ) -> Option<MappedView<T>> {
        let addr = self.base_addr().offset(offset);
        if !self.contains_range(addr, byte_len) {
            return None;
        }
        let region_offset = self.region_offset(addr);
        self.region.read_view(region_offset, addr, byte_len)
    }

    #[inline]
    pub(crate) fn borrowed_ptr<T: ByteRepr + 'static>(
        &self,
        offset: usize,
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
        self.find_range(addr, 1)?;
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

    /// Writes a typed relocation value without checked range validation.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// writable mapped memory owned by this image.
    #[inline]
    pub(crate) unsafe fn write_value<T: ByteRepr>(
        &self,
        addr: VmAddr,
        val: RelocValue<T>,
    ) -> Result<()> {
        let value = val.into_inner();
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        self.write_bytes(addr, bytes)
    }

    /// Updates a typed relocation value without checked range validation.
    ///
    /// # Safety
    /// The caller must ensure `addr..addr + size_of::<T>()` is backed by
    /// readable and writable mapped memory owned by this image.
    #[inline]
    pub(crate) unsafe fn update_value<T: ByteRepr + Copy>(
        &self,
        addr: VmAddr,
        update: impl FnOnce(T) -> T,
    ) -> Result<()> {
        if size_of::<T>() == 0 {
            return Ok(());
        }

        let mut value = MaybeUninit::<T>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>())
        };
        self.read_bytes(addr, bytes)?;
        let value = update(unsafe { value.assume_init() });
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        self.write_bytes(addr, bytes)
    }

    /// Gets the base address of the mapped memory.
    #[inline]
    pub fn base(&self) -> usize {
        self.base_addr().into_inner()
    }

    #[inline]
    pub(crate) fn base_addr(&self) -> VmAddr {
        VmAddr::new(self.base)
    }
}
