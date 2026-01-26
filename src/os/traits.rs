use core::ffi::c_void;

use super::{MapFlags, ProtFlags};
use crate::Result;

/// A trait for low-level memory mapping operations.
///
/// This trait provides a unified interface for memory-mapped I/O and anonymous memory allocation.
/// It abstracts platform-specific details, allowing the ELF loader to work across different systems.
///
/// # Safety
/// All methods are unsafe because they manipulate the process's virtual address space.
/// Improper use can cause memory corruption, crashes, or security vulnerabilities.
/// Implementors must ensure thread-safety and proper error handling.
///
/// # Example
/// ```rust,ignore
/// struct MyMmap;
///
/// unsafe impl Mmap for MyMmap {
///     unsafe fn mmap(
///         addr: Option<usize>,
///         len: usize,
///         prot: ProtFlags,
///         flags: MapFlags,
///         offset: usize,
///         fd: Option<isize>,
///         need_copy: &mut bool,
///     ) -> Result<*mut c_void> {
///         // Platform-specific implementation
///         todo!()
///     }
///
///     // Implement other required methods...
/// }
/// ```
pub trait Mmap {
    /// Maps a file or creates an anonymous mapping into memory.
    ///
    /// This method creates a memory mapping, either backed by a file (if `fd` is provided)
    /// or anonymous (if `fd` is `None`). The mapping can be used for efficient file I/O
    /// or dynamic memory allocation.
    ///
    /// # Arguments
    /// * `addr` - Preferred starting address (page-aligned). `None` lets the system choose.
    /// * `len` - Size of the mapping in bytes (rounded up to page size).
    /// * `prot` - Memory protection flags (read, write, execute permissions).
    /// * `flags` - Mapping configuration (private, fixed address, anonymous).
    /// * `offset` - File offset for file-backed mappings (must be page-aligned).
    /// * `fd` - File descriptor for file-backed mappings, or `None` for anonymous.
    /// * `need_copy` - Set to `true` if the implementation needs to copy data.
    ///
    /// # Returns
    /// A pointer to the mapped memory region on success.
    ///
    /// # Safety
    /// This function manipulates the process's address space. Ensure:
    /// - `addr` is page-aligned if specified.
    /// - `len` and `offset` are valid and don't cause overflow.
    /// - File descriptors are valid and accessible.
    unsafe fn mmap(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: Option<isize>,
        need_copy: &mut bool,
    ) -> Result<*mut c_void>;

    /// Creates an anonymous memory mapping.
    ///
    /// Allocates a region of memory not backed by any file, useful for dynamic memory
    /// allocation or creating private data areas.
    ///
    /// # Arguments
    /// * `addr` - Preferred starting address (page-aligned). `None` lets the system choose.
    /// * `len` - Size of the mapping in bytes.
    /// * `prot` - Initial memory protection flags.
    /// * `flags` - Mapping configuration flags.
    ///
    /// # Returns
    /// A pointer to the allocated memory region on success.
    ///
    /// # Safety
    /// Manipulates address space. Ensure `addr` is valid and page-aligned if specified.
    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<*mut c_void>;

    /// Unmaps a memory region, releasing the associated resources.
    ///
    /// Removes a memory mapping created by `mmap` or `mmap_anonymous`.
    /// After unmapping, accessing the memory region will cause a segmentation fault.
    ///
    /// # Arguments
    /// * `addr` - Pointer to the start of the region to unmap (must be page-aligned).
    /// * `len` - Size of the region in bytes.
    ///
    /// # Safety
    /// Ensure `addr` and `len` match the original mapping. Do not access the region after unmapping.
    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()>;

    /// Changes the protection of a memory region.
    ///
    /// Modifies the access permissions (read, write, execute) for an existing memory mapping.
    /// Commonly used for RELRO (RELocation Read-Only) protection in ELF loading, where
    /// sections are made read-only after relocations are applied.
    ///
    /// # Arguments
    /// * `addr` - Pointer to the start of the region (must be page-aligned).
    /// * `len` - Size of the region in bytes (rounded up to page boundary).
    /// * `prot` - New protection flags to apply.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the operation fails.
    ///
    /// # Safety
    /// Changing permissions can affect running code. Ensure no code is executing in the region
    /// when removing execute permissions. `addr` must be page-aligned.
    unsafe fn mprotect(addr: *mut c_void, len: usize, prot: ProtFlags) -> Result<()>;

    /// Reserves a region of virtual address space without committing physical memory.
    ///
    /// Reserves address space for future use without allocating physical storage.
    /// Useful for ELF loading when the total memory footprint is known in advance,
    /// allowing reservation of the entire address space before creating individual mappings.
    ///
    /// The default implementation uses `PROT_NONE` to reserve space without committing memory.
    ///
    /// # Arguments
    /// * `addr` - Preferred starting address, or `None` to let the system choose.
    /// * `len` - Size of the region to reserve in bytes.
    /// * `_use_file` - Hint whether the region will be file-backed (may be ignored).
    ///
    /// # Returns
    /// A pointer to the reserved region on success.
    ///
    /// # Safety
    /// Manipulates address space. The reserved region should not be accessed until properly mapped.
    unsafe fn mmap_reserve(
        addr: Option<usize>,
        len: usize,
        _use_file: bool,
    ) -> Result<*mut c_void> {
        let mut need_copy = false;
        // Reserve address space with PROT_NONE (no physical memory committed)
        unsafe {
            Self::mmap(
                addr,
                len,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                0,
                None,
                &mut need_copy,
            )
        }
    }
}
