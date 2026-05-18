use crate::{
    ByteRepr, Result,
    os::{MappedRegion, MappedView, VmAddr},
    relocation::RelocValue,
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
    access: SegmentAccess,
}

enum SegmentAccess {
    Linear(LinearAccess),
    Sparse,
}

struct LinearAccess {
    region: Arc<MappedRegion>,
    region_offset_bias: usize,
    mapped_start: usize,
    mapped_end: usize,
    contiguous: bool,
}

impl LinearAccess {
    fn new(slices: &[MappedSlice], contiguous: bool) -> Option<Self> {
        let first = slices.first()?;
        let region_ptr = Arc::as_ptr(&first.region);
        let region_offset_bias = first.region_offset.wrapping_sub(first.offset);
        let mapped_start = first.offset;
        let mapped_end = slices
            .last()
            .and_then(|slice| slice.offset.checked_add(slice.len))?;

        let is_linear = slices.iter().all(|slice| {
            core::ptr::addr_eq(Arc::as_ptr(&slice.region), region_ptr)
                && slice.region_offset.wrapping_sub(slice.offset) == region_offset_bias
        });

        is_linear.then(|| Self {
            region: first.region.clone(),
            region_offset_bias,
            mapped_start,
            mapped_end,
            contiguous,
        })
    }

    #[inline]
    fn contains_range(&self, start: usize, len: usize) -> bool {
        start >= self.mapped_start
            && start
                .checked_add(len)
                .is_some_and(|end| end <= self.mapped_end)
    }

    #[inline]
    fn region_offset(&self, start: usize) -> usize {
        start.wrapping_add(self.region_offset_bias)
    }
}

#[inline]
fn find_slice_index(slices: &[MappedSlice], start: usize, len: usize) -> Option<usize> {
    let idx = slices
        .partition_point(|slice| slice.offset() <= start)
        .checked_sub(1)?;
    slices[idx].contains_range(start, len).then_some(idx)
}

pub(crate) trait RelocWrite {
    /// Writes bytes to a relocation target without checked range validation.
    ///
    /// # Safety
    /// The caller must ensure `start..start + src.len()` is backed by writable
    /// mapped memory owned by this image.
    unsafe fn write_bytes(&mut self, start: usize, src: &[u8]);

    /// Reads bytes from a relocation target without checked range validation.
    ///
    /// # Safety
    /// The caller must ensure `start..start + dst.len()` is backed by readable
    /// mapped memory owned by this image.
    unsafe fn read_bytes(&mut self, start: usize, dst: &mut [u8]);

    /// Writes a typed relocation value without checked range validation.
    ///
    /// # Safety
    /// The caller must ensure `r_offset..r_offset + size_of::<T>()` is backed by
    /// writable mapped memory owned by this image.
    #[inline]
    unsafe fn write_value<T: ByteRepr>(&mut self, r_offset: usize, val: RelocValue<T>) {
        let value = val.into_inner();
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        unsafe { self.write_bytes(r_offset, bytes) };
    }

    /// Updates a typed relocation value without checked range validation.
    ///
    /// # Safety
    /// The caller must ensure `r_offset..r_offset + size_of::<T>()` is backed by
    /// readable and writable mapped memory owned by this image.
    #[inline]
    unsafe fn update_value<T: ByteRepr + Copy>(
        &mut self,
        r_offset: usize,
        update: impl FnOnce(T) -> T,
    ) {
        if size_of::<T>() == 0 {
            return;
        }

        let mut value = MaybeUninit::<T>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>())
        };
        unsafe { self.read_bytes(r_offset, bytes) };
        let value = update(unsafe { value.assume_init() });
        let bytes = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        unsafe { self.write_bytes(r_offset, bytes) };
    }
}

pub(crate) enum RelocWriter<'a> {
    Linear(LinearWriter<'a>),
    Sparse(SparseWriter<'a>),
}

pub(crate) struct LinearWriter<'a> {
    linear: &'a LinearAccess,
}

impl RelocWrite for LinearWriter<'_> {
    #[inline]
    unsafe fn write_bytes(&mut self, start: usize, src: &[u8]) {
        debug_assert!(self.linear.contains_range(start, src.len()));
        unsafe {
            self.linear
                .region
                .write_bytes(self.linear.region_offset(start), src)
        };
    }

    #[inline]
    unsafe fn read_bytes(&mut self, start: usize, dst: &mut [u8]) {
        debug_assert!(self.linear.contains_range(start, dst.len()));
        unsafe {
            self.linear
                .region
                .read_bytes(self.linear.region_offset(start), dst)
        };
    }
}

pub(crate) struct SparseWriter<'a> {
    slices: &'a [MappedSlice],
    current: usize,
}

impl<'a> SparseWriter<'a> {
    #[inline]
    fn new(slices: &'a [MappedSlice]) -> Self {
        Self { slices, current: 0 }
    }

    #[inline]
    fn slice_index(&mut self, start: usize, len: usize) -> usize {
        if self
            .slices
            .get(self.current)
            .is_some_and(|slice| slice.contains_range(start, len))
        {
            return self.current;
        }

        for idx in self.current.saturating_add(1)..self.slices.len() {
            let slice = &self.slices[idx];
            if slice.offset() > start {
                break;
            }
            if slice.contains_range(start, len) {
                self.current = idx;
                return idx;
            }
        }

        let idx = find_slice_index(self.slices, start, len)
            .expect("ELF relocation target is not fully backed by one mapped slice");
        self.current = idx;
        idx
    }
}

impl RelocWrite for SparseWriter<'_> {
    #[inline]
    unsafe fn write_bytes(&mut self, start: usize, src: &[u8]) {
        let slice = &self.slices[self.slice_index(start, src.len())];
        let region_offset = unsafe { ElfSegments::region_offset_unchecked(slice, start) };
        unsafe { slice.region.write_bytes(region_offset, src) };
    }

    #[inline]
    unsafe fn read_bytes(&mut self, start: usize, dst: &mut [u8]) {
        let slice = &self.slices[self.slice_index(start, dst.len())];
        let region_offset = unsafe { ElfSegments::region_offset_unchecked(slice, start) };
        unsafe { slice.region.read_bytes(region_offset, dst) };
    }
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
        find_slice_index(&self.slices, start, len).map(|idx| &self.slices[idx])
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
        let slices = alloc::vec![slice].into_boxed_slice();
        let access = SegmentAccess::Linear(
            LinearAccess::new(&slices, true).expect("single mapped slice must be linear"),
        );
        Self {
            base,
            slices,
            access,
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
        let contiguous = slices.windows(2).all(|pair| {
            pair[0]
                .offset
                .checked_add(pair[0].len)
                .is_some_and(|end| end == pair[1].offset)
        });
        let slices = slices.into_boxed_slice();
        let access = LinearAccess::new(&slices, contiguous)
            .map(SegmentAccess::Linear)
            .unwrap_or(SegmentAccess::Sparse);
        Self {
            base,
            slices,
            access,
        }
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

    #[inline]
    pub(crate) fn reloc_writer(&self) -> RelocWriter<'_> {
        match &self.access {
            SegmentAccess::Linear(linear) => RelocWriter::Linear(LinearWriter { linear }),
            SegmentAccess::Sparse => RelocWriter::Sparse(SparseWriter::new(&self.slices)),
        }
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
            .map(|slice| (slice.region.addr().get() as *mut _, slice.region.len()))
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
        if let SegmentAccess::Linear(linear) = &self.access
            && linear.contiguous
        {
            return addr
                .checked_sub(self.base.saturating_add(linear.mapped_start))
                .is_some_and(|offset| offset < linear.mapped_end - linear.mapped_start);
        }

        self.slices.iter().any(|slice| {
            addr.checked_sub(self.slice_base(slice))
                .is_some_and(|offset| offset < slice.len)
        })
    }

    /// Returns whether the mapped memory is one contiguous span with no gaps.
    pub fn is_contiguous_mapping(&self) -> bool {
        if let SegmentAccess::Linear(linear) = &self.access {
            return linear.contiguous;
        }

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

    /// Computes a region offset without validating that `start` belongs to `slice`.
    ///
    /// # Safety
    /// The caller must ensure `start` is inside `slice`.
    #[inline]
    unsafe fn region_offset_unchecked(slice: &MappedSlice, start: usize) -> usize {
        debug_assert!(start >= slice.offset);
        slice.region_offset + (start - slice.offset)
    }

    #[inline]
    pub(crate) fn read_view<T: ByteRepr + 'static>(
        &self,
        start: usize,
        byte_len: usize,
    ) -> Result<Option<MappedView<T>>> {
        let slice = self.runtime_slice(start, byte_len);
        let region_offset = Self::region_offset(slice, start);
        MappedView::read_region(
            &slice.region,
            region_offset,
            slice.region.addr().wrapping_add(region_offset),
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

    /// Translates an image VM address into a host-accessible pointer.
    ///
    /// Returns `None` when the address is outside this image or the backing
    /// mapping cannot be borrowed directly by the current process.
    #[inline]
    pub fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        let start = addr.get().checked_sub(self.base)?;
        let slice = self.find_slice(start, 1)?;
        let region_offset = Self::region_offset(slice, start);
        slice.region.host_ptr(region_offset)
    }

    #[inline]
    pub(crate) fn read_bytes(&self, start: usize, dst: &mut [u8]) -> Result<()> {
        let slice = self.runtime_slice(start, dst.len());
        unsafe {
            slice
                .region
                .read_bytes(Self::region_offset(slice, start), dst)
        };
        Ok(())
    }

    #[inline]
    pub(crate) fn write_bytes(&self, start: usize, src: &[u8]) -> Result<()> {
        let slice = self.runtime_slice(start, src.len());
        unsafe {
            slice
                .region
                .write_bytes(Self::region_offset(slice, start), src)
        };
        Ok(())
    }

    #[inline]
    pub(crate) fn zero_bytes(&self, start: usize, len: usize) -> Result<()> {
        let slice = self.runtime_slice(start, len);
        unsafe {
            slice
                .region
                .zero_bytes(Self::region_offset(slice, start), len)
        };
        Ok(())
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
