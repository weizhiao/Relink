use crate::{Result, relocation::RelocValue};
use core::{ffi::c_void, fmt::Debug};

/// The Memory mapping of elf object
///
/// This structure represents the complete memory mapping of an
/// ELF object, including all its segments and the overall memory
/// layout.
pub struct ElfSegments {
    /// Pointer to the mapped memory
    pub(crate) memory: *mut c_void,
    /// Offset from memory address to base address
    pub(crate) offset: usize,
    /// Total length of the mapped memory
    pub(crate) len: usize,
    /// Function pointer to the munmap function
    pub(crate) munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
}

impl Debug for ElfSegments {
    /// Format the ElfSegments for debugging
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfSegments")
            .field("base", &format_args!("0x{:x}", self.base()))
            .field("memory", &self.memory)
            .field("len", &self.len)
            .field("offset", &format_args!("0x{:x}", self.offset))
            .finish()
    }
}

impl Drop for ElfSegments {
    /// Unmap the memory when the ElfSegments is dropped
    fn drop(&mut self) {
        unsafe {
            (self.munmap)(self.memory, self.len).unwrap();
        }
    }
}

impl ElfSegments {
    #[inline]
    fn contains_range(&self, start: usize, len: usize) -> bool {
        start
            .checked_sub(self.offset)
            .and_then(|start| start.checked_add(len))
            .is_some_and(|end| end <= self.len)
    }

    #[inline]
    fn contains_offset(&self, offset: usize) -> bool {
        offset
            .checked_sub(self.offset)
            .is_some_and(|offset| offset < self.len)
    }

    /// Create a new ElfSegments instance
    ///
    /// # Arguments
    /// * `memory` - Pointer to the mapped memory
    /// * `len` - Length of the mapped memory
    /// * `munmap` - Function pointer to the munmap function
    ///
    /// # Returns
    /// A new ElfSegments instance
    pub(crate) fn new(
        memory: *mut c_void,
        len: usize,
        munmap: unsafe fn(*mut c_void, usize) -> Result<()>,
    ) -> Self {
        Self {
            memory,
            offset: 0,
            len,
            munmap,
        }
    }

    /// Get the length of the mapped memory
    ///
    /// # Returns
    /// The length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Get a slice from the mapped memory
    ///
    /// # Arguments
    /// * `start` - Start offset within the mapped memory
    /// * `len` - Length of the slice in bytes
    ///
    /// # Returns
    /// A static slice of the requested type
    ///
    /// # Safety
    /// The caller must ensure the requested range is valid and
    /// the type T is appropriate for the data at that location.
    #[inline]
    pub(crate) fn get_slice<T>(&self, start: usize, len: usize) -> &'static [T] {
        unsafe {
            debug_assert!(self.contains_range(start, len));
            core::slice::from_raw_parts(self.get_ptr::<T>(start), len / size_of::<T>())
        }
    }

    /// Get a mutable slice from the mapped memory
    ///
    /// # Arguments
    /// * `start` - Start offset within the mapped memory
    /// * `len` - Length of the slice in bytes
    ///
    /// # Returns
    /// A static mutable slice of the requested type
    ///
    /// # Safety
    /// The caller must ensure the requested range is valid and
    /// the type T is appropriate for the data at that location.
    pub(crate) fn get_slice_mut<T>(&self, start: usize, len: usize) -> &'static mut [T] {
        unsafe {
            debug_assert!(self.contains_range(start, len));
            core::slice::from_raw_parts_mut(self.get_mut_ptr::<T>(start), len / size_of::<T>())
        }
    }

    /// Get a pointer from the mapped memory
    ///
    /// # Arguments
    /// * `offset` - Offset within the mapped memory
    ///
    /// # Returns
    /// A pointer of the requested type
    ///
    /// # Safety
    /// The caller must ensure the requested offset is valid and
    /// the type T is appropriate for the data at that location.
    #[inline]
    pub(crate) fn get_ptr<T>(&self, offset: usize) -> *const T {
        debug_assert!(self.contains_offset(offset));
        (self.base() + offset) as *const T
    }

    /// Get a mutable pointer from the mapped memory
    ///
    /// # Arguments
    /// * `offset` - Offset within the mapped memory
    ///
    /// # Returns
    /// A mutable pointer of the requested type
    ///
    /// # Safety
    /// The caller must ensure the requested offset is valid and
    /// the type T is appropriate for the data at that location.
    #[inline]
    pub(crate) fn get_mut_ptr<T>(&self, offset: usize) -> *mut T {
        self.get_ptr::<T>(offset) as *mut T
    }

    /// Write a value into the mapped memory
    #[inline]
    pub(crate) fn write<T>(&self, r_offset: usize, val: RelocValue<T>) {
        unsafe { self.get_mut_ptr::<T>(r_offset).write(val.0) };
    }

    /// Get the base address of the mapped memory
    ///
    /// The base address is calculated as memory address minus offset.
    ///
    /// # Returns
    /// The base address
    #[inline]
    pub fn base(&self) -> usize {
        self.memory as usize - self.offset
    }
}
