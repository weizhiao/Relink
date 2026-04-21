use crate::{
    Result, logging,
    relocation::{RelocAddr, RelocValue},
    sync::Arc,
};
use alloc::{boxed::Box, vec::Vec};
use core::{ffi::c_void, fmt::Debug, mem::size_of, ptr::NonNull};

pub(crate) struct ElfMemoryBacking {
    memory: *mut c_void,
    len: usize,
    munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
}

impl ElfMemoryBacking {
    #[inline]
    fn new(
        memory: *mut c_void,
        len: usize,
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
    ) -> Self {
        Self {
            memory,
            len,
            munmap,
        }
    }
}

impl Drop for ElfMemoryBacking {
    fn drop(&mut self) {
        let res = unsafe { (self.munmap)(self.memory, self.len) };
        debug_assert!(res.is_ok(), "failed to unmap ELF segments");
        if let Err(err) = res {
            logging::error!("failed to unmap ELF segments: {err}");
        }
    }
}

// Safety: the backing only owns an mmap-style region and unmaps it on drop.
unsafe impl Send for ElfMemoryBacking {}
// Safety: the backing does not expose interior mutability beyond the mapped bytes themselves.
unsafe impl Sync for ElfMemoryBacking {}

#[derive(Clone)]
pub(crate) struct ElfSegmentSlice {
    offset: usize,
    len: usize,
    // This shared owner keeps the mapped arena alive even when address math
    // only needs the slice bounds at runtime.
    #[cfg_attr(not(windows), allow(dead_code))]
    backing: Arc<ElfMemoryBacking>,
}

impl ElfSegmentSlice {
    #[inline]
    pub(crate) fn new(offset: usize, len: usize, backing: Arc<ElfMemoryBacking>) -> Self {
        Self {
            offset,
            len,
            backing,
        }
    }

    #[inline]
    fn contains_range(&self, start: usize, len: usize) -> bool {
        start
            .checked_sub(self.offset)
            .and_then(|delta| delta.checked_add(len))
            .is_some_and(|end| end <= self.len)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }
}

/// The mapped memory of an ELF object.
///
/// This type now supports both a single contiguous legacy mapping and a sparse
/// collection of mapped slices backed by one or more shared arena mappings.
/// The slices are kept sorted by offset and must not overlap.
pub struct ElfSegments {
    base: usize,
    slices: Box<[ElfSegmentSlice]>,
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
    fn find_slice(&self, start: usize, len: usize) -> Option<&ElfSegmentSlice> {
        self.slices
            .iter()
            .find(|slice| slice.contains_range(start, len))
    }

    #[inline]
    fn slice_base(&self, slice: &ElfSegmentSlice) -> usize {
        self.base.saturating_add(slice.offset)
    }

    #[inline]
    fn slice_end(&self, slice: &ElfSegmentSlice) -> usize {
        self.slice_base(slice).saturating_add(slice.len)
    }

    /// Create a new contiguous [`ElfSegments`] instance with `base == memory`.
    pub(crate) fn new(
        memory: *mut c_void,
        len: usize,
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
    ) -> Self {
        Self::with_base(memory, len, munmap, memory as usize, 0)
    }

    /// Create a new contiguous [`ElfSegments`] instance whose mapped bytes begin
    /// at the module-relative `offset`.
    pub(crate) fn with_base(
        memory: *mut c_void,
        len: usize,
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
        base: usize,
        offset: usize,
    ) -> Self {
        let backing = Arc::new(ElfMemoryBacking::new(memory, len, munmap));
        let slice = ElfSegmentSlice::new(offset, len, backing);
        Self {
            base,
            slices: alloc::vec![slice].into_boxed_slice(),
        }
    }

    /// Creates an [`ElfSegments`] instance from explicit mapped slices.
    pub(crate) fn from_slices(base: usize, mut slices: Vec<ElfSegmentSlice>) -> Self {
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

    /// Creates one shared backing owner for a mapped region.
    pub(crate) fn create_backing(
        memory: *mut c_void,
        len: usize,
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
    ) -> Arc<ElfMemoryBacking> {
        Arc::new(ElfMemoryBacking::new(memory, len, munmap))
    }

    /// Creates one mapped slice descriptor backed by a shared owner.
    #[inline]
    pub(crate) fn slice(
        offset: usize,
        len: usize,
        backing: Arc<ElfMemoryBacking>,
    ) -> ElfSegmentSlice {
        ElfSegmentSlice::new(offset, len, backing)
    }

    /// Rebinds the module base address while preserving the existing slice layout.
    #[inline]
    pub(crate) fn set_base(&mut self, base: usize) {
        self.base = base;
    }

    /// Returns the first mapped backing region, when this object owns one.
    #[inline]
    #[cfg(windows)]
    pub(crate) fn primary_backing(&self) -> Option<(*mut c_void, usize)> {
        self.slices
            .first()
            .map(|slice| (slice.backing.memory, slice.backing.len))
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

    /// Returns whether the backing memory is one contiguous span with no gaps.
    pub fn is_contiguous_mapping(&self) -> bool {
        self.slices
            .windows(2)
            .all(|pair| self.slice_end(&pair[0]) == self.slice_base(&pair[1]))
    }

    /// Gets a slice from the mapped memory.
    #[inline]
    pub(crate) fn get_slice<T>(&self, start: usize, len: usize) -> &'static [T] {
        if len == 0 {
            return unsafe { core::slice::from_raw_parts(NonNull::<T>::dangling().as_ptr(), 0) };
        }
        let byte_len = len;
        assert!(
            self.find_slice(start, byte_len).is_some(),
            "ELF segment range is not fully backed by one mapped slice",
        );
        unsafe { core::slice::from_raw_parts(self.get_ptr::<T>(start), len / size_of::<T>()) }
    }

    /// Gets a mutable slice from the mapped memory.
    #[inline]
    pub(crate) fn get_slice_mut<T>(&self, start: usize, len: usize) -> &'static mut [T] {
        if len == 0 {
            return unsafe {
                core::slice::from_raw_parts_mut(NonNull::<T>::dangling().as_ptr(), 0)
            };
        }
        let byte_len = len;
        assert!(
            self.find_slice(start, byte_len).is_some(),
            "ELF segment range is not fully backed by one mapped slice",
        );
        unsafe {
            core::slice::from_raw_parts_mut(self.get_mut_ptr::<T>(start), len / size_of::<T>())
        }
    }

    /// Gets a pointer from the mapped memory.
    #[inline]
    pub(crate) fn get_ptr<T>(&self, offset: usize) -> *const T {
        assert!(
            self.find_slice(offset, size_of::<T>()).is_some() || size_of::<T>() == 0,
            "ELF segment pointer is not backed by a mapped slice",
        );
        self.base_addr().offset(offset).as_ptr()
    }

    /// Gets a mutable pointer from the mapped memory.
    #[inline]
    pub(crate) fn get_mut_ptr<T>(&self, offset: usize) -> *mut T {
        self.get_ptr::<T>(offset) as *mut T
    }

    /// Writes a value into the mapped memory.
    #[inline]
    pub(crate) fn write<T>(&self, r_offset: usize, val: RelocValue<T>) {
        unsafe { self.get_mut_ptr::<T>(r_offset).write(val.into_inner()) };
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
