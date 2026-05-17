use crate::{
    ByteRepr, Result,
    os::{MappedRegion, MappedView, TargetAddr},
    relocation::{RelocAddr, RelocValue},
    sync::Arc,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt::Debug,
    mem::{MaybeUninit, size_of},
    ptr::NonNull,
};

use super::MappedSlice;

/// The mapped memory of an ELF object.
///
/// This type now supports both a single contiguous legacy mapping and a sparse
/// collection of mapped slices backed by one or more shared arena mappings.
/// The slices are kept sorted by offset and must not overlap.
pub struct ElfSegments {
    base: usize,
    slices: Box<[MappedSlice]>,
}

impl Debug for ElfSegments {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let slices = self
            .slices
            .iter()
            .map(|slice| (slice.offset(), slice.len()))
            .collect::<Vec<_>>();
        f.debug_struct("ElfSegments")
            .field("base", &format_args!("0x{:x}", self.base()))
            .field("slices", &slices)
            .finish()
    }
}

impl ElfSegments {
    #[inline]
    fn find_slice(&self, start: usize, len: usize) -> Option<&MappedSlice> {
        self.slices
            .iter()
            .find(|slice| slice.contains_range(start, len))
    }

    #[inline]
    fn slice_base(&self, slice: &MappedSlice) -> usize {
        self.base.saturating_add(slice.offset)
    }

    #[inline]
    fn slice_end(&self, slice: &MappedSlice) -> usize {
        self.slice_base(slice).saturating_add(slice.len)
    }

    /// Create a new contiguous [`ElfSegments`] instance whose mapped bytes begin
    /// at the module-relative `offset`.
    pub(crate) fn new(region: MappedRegion, base: usize, offset: usize) -> Self {
        let len = region.len();
        let region = Arc::new(region);
        let slice = MappedSlice::new(offset, len, 0, region);
        Self {
            base,
            slices: alloc::vec![slice].into_boxed_slice(),
        }
    }

    /// Creates an [`ElfSegments`] instance from explicit mapped slices.
    pub(crate) fn from_slices(base: usize, mut slices: Vec<MappedSlice>) -> Self {
        slices.sort_by_key(|slice| (slice.offset(), slice.len()));
        for pair in slices.windows(2) {
            let previous = &pair[0];
            let next = &pair[1];
            let previous_end = previous
                .offset
                .checked_add(previous.len)
                .expect("ELF segment slice range overflowed");
            assert!(
                previous_end <= next.offset,
                "ELF segment slices must not overlap",
            );
        }
        let slices = slices.into_boxed_slice();
        Self { base, slices }
    }

    /// Creates one shared mapped region owner.
    pub(crate) fn create_region(region: MappedRegion) -> Arc<MappedRegion> {
        Arc::new(region)
    }

    /// Creates one mapped slice descriptor covered by a shared region.
    #[inline]
    pub(crate) fn create_slice(
        offset: usize,
        len: usize,
        region_offset: usize,
        region: Arc<MappedRegion>,
    ) -> MappedSlice {
        MappedSlice::new(offset, len, region_offset, region)
    }

    /// Rebinds the module base address while preserving the existing slice layout.
    #[inline]
    pub(crate) fn set_base(&mut self, base: usize) {
        self.base = base;
    }

    /// Returns the first mapped region, when this object owns one.
    #[inline]
    #[cfg(windows)]
    pub(crate) fn primary_region(&self) -> Option<(*mut core::ffi::c_void, usize)> {
        self.slices
            .first()
            .map(|slice| (slice.region.addr().as_mut_ptr(), slice.region.len()))
    }

    /// Returns whether no slices are mapped.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slices.is_empty()
    }

    /// Returns the lowest runtime address covered by this image's mapped slices.
    #[inline]
    pub fn mapped_base(&self) -> usize {
        self.slices
            .first()
            .map(|slice| self.slice_base(slice))
            .unwrap_or(0)
    }

    /// Returns the length of the bounding runtime span covered by mapped slices.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        let Some((first, last)) = self.slices.first().zip(self.slices.last()) else {
            return 0;
        };
        let base = self.slice_base(first);
        let end = self.slice_end(last);
        end.saturating_sub(base)
    }

    /// Returns whether `addr` is inside one of this image's mapped slices.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        self.slices.iter().any(|slice| {
            addr.checked_sub(self.slice_base(slice))
                .is_some_and(|offset| offset < slice.len)
        })
    }

    /// Returns whether the mapped memory is one contiguous span with no gaps.
    pub fn is_contiguous_mapping(&self) -> bool {
        self.slices
            .windows(2)
            .all(|pair| self.slice_end(&pair[0]) == self.slice_base(&pair[1]))
    }

    #[inline]
    fn runtime_slice(&self, start: usize, len: usize) -> &MappedSlice {
        self.find_slice(start, len)
            .expect("ELF segment range is not fully backed by one mapped slice")
    }

    #[inline]
    fn region_offset(slice: &MappedSlice, start: usize) -> usize {
        slice
            .region_offset(start)
            .expect("ELF segment range precedes mapped slice")
    }

    #[inline]
    fn runtime_addr(&self, start: usize, len: usize) -> TargetAddr {
        let slice = self.runtime_slice(start, len);
        slice
            .region
            .addr()
            .wrapping_add(Self::region_offset(slice, start))
    }

    #[inline]
    pub(crate) fn write_bytes(&self, start: usize, src: &[u8]) -> Result<()> {
        let slice = self.runtime_slice(start, src.len());
        unsafe {
            slice
                .region
                .write_bytes_unchecked(Self::region_offset(slice, start), src)
        }
    }

    #[inline]
    pub(crate) fn zero_bytes(&self, start: usize, len: usize) -> Result<()> {
        let slice = self.runtime_slice(start, len);
        unsafe {
            slice
                .region
                .zero_bytes_unchecked(Self::region_offset(slice, start), len)
        }
    }

    #[inline]
    pub(crate) fn read_bytes(&self, start: usize, dst: &mut [u8]) -> Result<()> {
        let slice = self.runtime_slice(start, dst.len());
        unsafe {
            slice
                .region
                .read_bytes_unchecked(Self::region_offset(slice, start), dst)
        }
    }

    #[inline]
    pub(crate) fn read_view<T: ByteRepr + 'static>(
        &self,
        start: usize,
        byte_len: usize,
    ) -> Result<Option<MappedView<T>>> {
        let slice = self.runtime_slice(start, byte_len);
        MappedView::read_region(
            &slice.region,
            Self::region_offset(slice, start),
            self.runtime_addr(start, byte_len),
            byte_len,
        )
    }

    #[inline]
    pub(crate) fn borrowed_ptr<T: ByteRepr + 'static>(
        &self,
        start: usize,
        byte_len: usize,
    ) -> Result<Option<NonNull<T>>> {
        Ok(self
            .read_view::<T>(start, byte_len)?
            .and_then(|view| view.as_slice().first().map(NonNull::from)))
    }

    #[inline]
    pub(crate) fn write_value<T: ByteRepr>(
        &self,
        r_offset: usize,
        val: RelocValue<T>,
    ) -> Result<()> {
        let value = val.into_inner();
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        let slice = self.runtime_slice(r_offset, bytes.len());
        unsafe {
            slice
                .region
                .write_bytes_unchecked(Self::region_offset(slice, r_offset), bytes)
        }
    }

    #[inline]
    pub(crate) fn update_value<T: ByteRepr + Copy>(
        &self,
        r_offset: usize,
        update: impl FnOnce(T) -> T,
    ) -> Result<()> {
        if size_of::<T>() == 0 {
            return Ok(());
        }

        let slice = self.runtime_slice(r_offset, size_of::<T>());
        let region_offset = Self::region_offset(slice, r_offset);
        let mut value = MaybeUninit::<T>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>())
        };
        unsafe {
            slice.region.read_bytes_unchecked(region_offset, bytes)?;
            let value = update(value.assume_init());
            let bytes =
                core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>());
            slice.region.write_bytes_unchecked(region_offset, bytes)
        }
    }

    /// Gets the base address of the mapped memory.
    #[inline]
    pub fn base(&self) -> usize {
        self.base_addr().into_inner()
    }

    #[inline]
    pub(crate) fn base_addr(&self) -> RelocAddr {
        RelocAddr::new(self.base)
    }
}
