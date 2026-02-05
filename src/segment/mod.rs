//! The Memory mapping of elf object
//!
//! This module provides functionality for mapping ELF segments into memory.
//! It handles the creation of memory segments, mapping them from file or
//! anonymous sources, and managing their protection and lifecycle.

use crate::input::ElfReader;
use crate::os::{MapFlags, Mmap, ProtFlags};
use crate::{Result, elf::Phdr, relocation::RelocValue};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::fmt::Debug;

pub(crate) mod program;
pub(crate) mod section;

/// Standard page size used for memory mapping operations
pub const PAGE_SIZE: usize = 0x1000;

/// Mask used to align addresses to page boundaries
pub const MASK: usize = !(PAGE_SIZE - 1);

/// Address representation for ELF segments
///
/// This enum represents either a relative address (offset from base)
/// or an absolute address (fully resolved virtual address).
enum Address {
    /// Relative address (offset from base address)
    Relative(usize),

    /// Absolute address (fully resolved virtual address)
    Absolute(usize),
}

impl Address {
    /// Get the absolute address
    ///
    /// # Returns
    /// The absolute address value
    ///
    /// # Panics
    /// Panics if called on a Relative address variant
    fn absolute_addr(&self) -> usize {
        match self {
            Address::Relative(_) => unreachable!(),
            Address::Absolute(addr) => *addr,
        }
    }

    /// Get the relative address
    ///
    /// # Returns
    /// The relative address value
    ///
    /// # Panics
    /// Panics if called on an Absolute address variant
    fn relative_addr(&self) -> usize {
        match self {
            Address::Relative(addr) => *addr,
            Address::Absolute(_) => unreachable!(),
        }
    }
}

/// Information about a file mapping within a segment
///
/// This structure describes how a portion of a file is mapped
/// into a memory segment.
#[derive(Debug)]
struct FileMapInfo {
    /// Start offset within the segment
    start: usize,
    /// Size of the file data in bytes
    filesz: usize,
    /// Offset within the file
    offset: usize,
}

/// An ELF segment in memory
///
/// This structure represents a loaded ELF segment with all the
/// information needed to manage its memory mapping, protection,
/// and data content.
pub(crate) struct ElfSegment {
    /// Address of the segment in memory
    addr: Address,
    /// Memory protection flags for the segment
    prot: ProtFlags,
    /// Memory mapping flags for the segment
    flags: MapFlags,
    /// Total length of the segment in bytes
    len: usize,
    /// Size of zero-filled area at the end of the segment
    zero_size: usize,
    /// Size of content (non-zero) area in the segment
    content_size: usize,
    /// Information about file mappings within this segment
    map_info: Vec<FileMapInfo>,
    /// Indicates if data needs to be copied manually
    need_copy: bool,
    /// Indicates if this segment comes from a relocatable object
    from_relocatable: bool,
}

impl ElfSegment {
    /// Rebase the segment with a new base address
    ///
    /// This method converts a relative address to an absolute address
    /// by adding the provided base address.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the relative address
    fn rebase(&mut self, base: usize) {
        self.addr = Address::Absolute(base + self.addr.relative_addr());
    }

    /// Map the segment into memory
    ///
    /// This method maps the segment into memory using the appropriate
    /// memory mapping operations based on the segment's properties.
    ///
    /// # Arguments
    /// * `object` - The ELF object to map data from
    ///
    /// # Returns
    /// * `Ok(())` - If mapping succeeds
    /// * `Err(Error)` - If mapping fails
    fn mmap_segment<M: Mmap>(&mut self, object: &mut impl ElfReader) -> Result<()> {
        let mut need_copy = false;
        let len = self.len;
        let addr = self.addr.absolute_addr();

        // For relocatable objects, we need read-write permissions initially
        let prot = if self.from_relocatable {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        } else {
            self.prot
        };

        debug_assert!(len % PAGE_SIZE == 0);

        // Map the segment based on file mapping information
        if self.map_info.len() == 1 {
            debug_assert!(self.map_info[0].offset % PAGE_SIZE == 0);
            unsafe {
                M::mmap(
                    Some(addr),
                    len,
                    prot,
                    self.flags,
                    self.map_info[0].offset,
                    object.as_fd(),
                    &mut need_copy,
                )
            }?
        } else {
            unsafe { M::mmap(Some(addr), len, prot, self.flags, 0, None, &mut need_copy) }?
        };

        #[cfg(feature = "log")]
        log::trace!(
            "[Mmap] address: 0x{:x}, length: {}, flags: {:?}, zero_size: {}, map_info: {:?}",
            addr,
            len,
            prot,
            self.zero_size,
            self.map_info
        );

        self.need_copy = need_copy;
        Ok(())
    }

    /// Copy data into the mapped segment
    ///
    /// This method copies data from the ELF object into the mapped
    /// memory segment when manual copying is required.
    ///
    /// # Arguments
    /// * `object` - The ELF object to copy data from
    ///
    /// # Returns
    /// * `Ok(())` - If copying succeeds
    /// * `Err(Error)` - If copying fails
    fn copy_data(&self, object: &mut impl ElfReader) -> Result<()> {
        if self.need_copy {
            let ptr = self.addr.absolute_addr() as *mut u8;
            for info in self.map_info.iter() {
                unsafe {
                    let dest = core::slice::from_raw_parts_mut(ptr.add(info.start), info.filesz);
                    object.read(dest, info.offset)?;
                }
            }
        }
        Ok(())
    }

    /// Change memory protection of the segment
    ///
    /// This method adjusts the memory protection of the segment
    /// after initial mapping, typically to make it executable
    /// or read-only as required.
    ///
    /// # Returns
    /// * `Ok(())` - If protection change succeeds
    /// * `Err(Error)` - If protection change fails
    fn mprotect<M: Mmap>(&self) -> Result<()> {
        if self.need_copy || self.from_relocatable {
            let len = self.len;
            debug_assert!(len % PAGE_SIZE == 0);
            let addr = self.addr.absolute_addr();
            unsafe { M::mprotect(addr as _, len, self.prot) }?;

            #[cfg(feature = "log")]
            log::trace!(
                "[Mprotect] address: 0x{:x}, length: {}, prot: {:?}",
                addr,
                len,
                self.prot,
            );
        }
        Ok(())
    }

    /// Fill zero-initialized areas of the segment
    ///
    /// This method fills any zero-initialized areas of the segment
    /// with zeros, either by writing directly or by mapping
    /// anonymous pages.
    ///
    /// # Returns
    /// * `Ok(())` - If filling succeeds
    /// * `Err(Error)` - If filling fails
    fn fill_zero<M: Mmap>(&self) -> Result<()> {
        if self.zero_size > 0 {
            // Fill the partial page with zeros
            let zero_start = self.addr.absolute_addr() + self.content_size;
            let zero_end = roundup(zero_start, PAGE_SIZE);
            let write_len = zero_end - zero_start;
            let ptr = zero_start as *mut u8;
            unsafe {
                ptr.write_bytes(0, write_len);
            };

            // If there's more zero space beyond the partial page,
            // map anonymous pages for it
            if write_len < self.zero_size {
                // The remaining space is guaranteed to be page-aligned
                let zero_mmap_addr = zero_end;
                let zero_mmap_len = self.zero_size - write_len;

                // For relocatable objects, we need read-write permissions initially
                let prot = if self.from_relocatable {
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
                } else {
                    self.prot
                };

                unsafe {
                    M::mmap_anonymous(
                        zero_mmap_addr,
                        zero_mmap_len,
                        prot,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Trait for building ELF segments
///
/// This trait provides the interface for creating and managing
/// ELF segments during the loading process.
pub(crate) trait SegmentBuilder {
    /// Create the address space for the segments
    ///
    /// # Returns
    /// * `Ok(ElfSegments)` - The created segment space
    /// * `Err(Error)` - If creation fails
    fn create_space<M: Mmap>(&mut self) -> Result<ElfSegments>;

    /// Create the individual segments
    ///
    /// # Returns
    /// * `Ok(())` - If creation succeeds
    /// * `Err(Error)` - If creation fails
    fn create_segments(&mut self) -> Result<()>;

    /// Get mutable reference to segments
    ///
    /// # Returns
    /// Mutable reference to the segment array
    fn segments_mut(&mut self) -> &mut [ElfSegment];

    /// Get reference to segments
    ///
    /// # Returns
    /// Reference to the segment array
    fn segments(&self) -> &[ElfSegment];

    /// Load segments into memory
    ///
    /// This method orchestrates the loading of all segments
    /// into memory, including mapping, data copying, and
    /// zero-filling.
    ///
    /// # Arguments
    /// * `object` - The ELF object to load segments from
    ///
    /// # Returns
    /// * `Ok(ElfSegments)` - The loaded segments
    /// * `Err(Error)` - If loading fails
    fn load_segments<M: Mmap>(&mut self, object: &mut impl ElfReader) -> Result<ElfSegments> {
        // Create the address space for segments
        let space = self.create_space::<M>()?;
        self.create_segments()?;
        let segments = self.segments_mut();
        let base = space.base();

        #[cfg(windows)]
        let mut last_addr = space.memory as usize;

        // Process each segment
        for segment in segments.iter_mut() {
            segment.rebase(base);
            #[cfg(windows)]
            if object.as_fd().is_some() {
                let addr = segment.addr.absolute_addr();
                let len = segment.len;
                if addr > last_addr {
                    crate::os::virtual_free(last_addr, addr - last_addr)?;
                }
                let space_end = space.memory as usize + space.len();
                if addr + len < space_end {
                    crate::os::virtual_free(addr + len, space_end - (addr + len))?;
                }
                last_addr = addr + len;
            }
            segment.mmap_segment::<M>(object)?;
            segment.copy_data(object)?;
            segment.fill_zero::<M>()?;
        }
        Ok(space)
    }

    /// Change memory protection of all segments
    ///
    /// This method adjusts the memory protection of all segments
    /// after initial mapping.
    ///
    /// # Returns
    /// * `Ok(())` - If protection changes succeed
    /// * `Err(Error)` - If protection changes fail
    fn mprotect<M: Mmap>(&self) -> Result<()> {
        let segments = self.segments();
        for segment in segments.iter() {
            segment.mprotect::<M>()?;
        }
        Ok(())
    }
}

/// RELRO (RELocation Read-Only) segment information
///
/// This structure holds information about a RELRO segment,
/// which is used to make certain segments read-only after
/// relocation to improve security.
#[allow(unused)]
pub(crate) struct ELFRelro {
    /// Virtual address of the RELRO segment
    addr: usize,
    /// Size of the RELRO segment
    len: usize,
    /// Function pointer to the mprotect function
    mprotect: unsafe fn(*mut c_void, usize, ProtFlags) -> Result<()>,
}

impl ELFRelro {
    /// Create a new RELRO segment
    ///
    /// # Arguments
    /// * `phdr` - The program header describing the segment
    /// * `base` - The base address to which the segment is loaded
    ///
    /// # Returns
    /// A new ELFRelro instance
    pub(crate) fn new<M: Mmap>(phdr: &Phdr, base: usize) -> ELFRelro {
        ELFRelro {
            addr: base + phdr.p_vaddr as usize,
            len: phdr.p_memsz as usize,
            mprotect: M::mprotect,
        }
    }
}

/// Round up a value to the nearest alignment boundary
///
/// # Arguments
/// * `x` - The value to round up
/// * `align` - The alignment boundary
///
/// # Returns
/// The rounded up value
#[inline]
fn roundup(x: usize, align: usize) -> usize {
    if align == 0 {
        return x;
    }
    (x + align - 1) & !(align - 1)
}

/// Round down a value to the nearest alignment boundary
///
/// # Arguments
/// * `x` - The value to round down
/// * `align` - The alignment boundary
///
/// # Returns
/// The rounded down value
#[inline]
fn rounddown(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

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

impl ELFRelro {
    /// Apply RELRO protection to the segment
    ///
    /// This method makes the RELRO segment read-only to improve security.
    ///
    /// # Returns
    /// * `Ok(())` - If RELRO protection is applied successfully
    /// * `Err(Error)` - If RELRO protection fails
    #[inline]
    pub(crate) fn relro(&self) -> Result<()> {
        let end = roundup(self.addr + self.len, PAGE_SIZE);
        let start = self.addr & MASK;
        let start_addr = start as *mut c_void;
        unsafe {
            (self.mprotect)(start_addr, end - start, ProtFlags::PROT_READ)?;
        }
        Ok(())
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
        ElfSegments {
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
            // Ensure the slice is within the mapped ELF segments
            debug_assert!(start + len - self.offset <= self.len);
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
            // Ensure the slice is within the mapped ELF segments
            debug_assert!(start + len - self.offset <= self.len);
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
        // Ensure offset is within the mapped ELF segments
        debug_assert!(offset - self.offset < self.len);
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
