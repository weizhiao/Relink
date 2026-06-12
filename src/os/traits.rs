use super::{MadviseAdvice, MapFlags, MappedRegion, PageSize, ProtFlags, RegionAccess, VmAddr};
use crate::Result;
use alloc::sync::Arc;

/// A trait for low-level memory mapping operations.
///
/// Loading first creates an owning address space with [`Mmap::create_space`].
/// Later calls fill parts of that space with file-backed pages, writable copy
/// targets, or anonymous zero pages. Only the space owns the final lifetime;
/// per-segment mapping methods do not return temporary regions.
///
/// # Safety
/// All methods are unsafe because they manipulate the process's virtual address space.
/// Improper use can cause memory corruption, crashes, or security vulnerabilities.
/// Implementors must ensure thread-safety and proper error handling.
///
/// # Example
/// ```rust,ignore
/// struct MyMmap {
///     // Put loader/task/address-space context here.
/// }
///
/// impl Mmap for MyMmap {
///     unsafe fn create_space(
///         &self,
///         addr: Option<VmAddr>,
///         len: usize,
///         prot: ProtFlags,
///         populate_later: bool,
///     ) -> Result<MappedRegion> {
///         todo!()
///     }
///
///     // Implement other required methods...
/// }
/// ```
pub trait Mmap: Send + Sync + 'static {
    /// Region type created by this mapping backend.
    type Region: RegionAccess;

    /// Returns the base page size required by this mapping environment.
    ///
    /// Implementations that can query the host should return the active system
    /// page size. Bare-metal or syscall-only implementations can keep the
    /// default 4 KiB base page.
    #[inline]
    fn page_size(&self) -> PageSize {
        PageSize::Base
    }

    /// Creates the owning virtual address space for a loaded image or arena.
    ///
    /// # Arguments
    /// * `addr` - Preferred starting address (page-aligned). `None` lets the system choose.
    /// * `len` - Size of the space in bytes.
    /// * `prot` - Initial protection for committed spaces.
    /// * `populate_later` - Whether file/zero pages will later replace subranges.
    ///
    /// # Safety
    /// Manipulates address space. `addr` must be page-aligned if specified.
    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>>;

    /// Creates a non-owning region view for an address range that is already mapped.
    ///
    /// This is used for startup images that were mapped before the loader took
    /// control. The returned region must not unmap the range on drop, but it
    /// should still support operations such as [`RegionAccess::mprotect`] when
    /// the backend can apply them.
    ///
    /// # Safety
    /// `addr..addr + len` must describe a valid mapped range for the returned
    /// region's lifetime.
    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>>;

    /// Maps file-backed pages into an already-created space.
    ///
    /// The mapped range is owned by the surrounding space created with
    /// [`Mmap::create_space`].
    unsafe fn map_file_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()>;

    /// Maps or commits anonymous zero-filled pages into an already-created space.
    ///
    /// The mapped range is owned by the surrounding space created with
    /// [`Mmap::create_space`].
    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<()>;

    /// Unmaps a memory region, releasing the associated resources.
    ///
    /// Removes a memory space created by [`Mmap::create_space`].
    /// After unmapping, accessing the memory region will cause a segmentation fault.
    ///
    /// # Arguments
    /// * `addr` - Pointer to the start of the region to unmap (must be page-aligned).
    /// * `len` - Size of the region in bytes.
    ///
    /// # Safety
    /// Ensure `addr` and `len` match the original mapping. Do not access the region after unmapping.
    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()>;

    /// Give advice about the use of memory.
    ///
    /// The activity performed is highly dependent on the "advice" being applied.
    /// See the madvise(2) man page (<https://man7.org/linux/man-pages/man2/madvise.2.html>)
    /// for more details.
    ///
    /// # Arguments
    /// * `addr` - Pointer to the start of a memory region to operate on (must be page-aligned).
    /// * `len` - Size of span of memory we're influencing (doesn't have to be the full segment).
    /// * `behavior` - The specific "advice" being applied.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the operation fails.
    ///
    /// Older kernel versions may not support newer behavior/advice values.
    /// Unknown behavior values will return EINVAL.
    ///
    /// # Safety
    /// Highly dependent on the advice being applied. Some advice values do
    /// nothing except for updating bookkeeping inside the kernel. Others (like
    /// MADV_REMOVE) effectively free the memory. Caller is responsible for
    /// taking appropriate action given the advice applied.
    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()>;

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
    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()>;
}

impl<M> Mmap for Arc<M>
where
    M: Mmap + ?Sized,
{
    type Region = M::Region;

    #[inline]
    fn page_size(&self) -> PageSize {
        (**self).page_size()
    }

    #[inline]
    unsafe fn create_space(
        &self,
        addr: Option<VmAddr>,
        len: usize,
        prot: ProtFlags,
        populate_later: bool,
    ) -> Result<MappedRegion<Self::Region>> {
        unsafe { (**self).create_space(addr, len, prot, populate_later) }
    }

    #[inline]
    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        unsafe { (**self).alias_space(addr, len) }
    }

    #[inline]
    unsafe fn map_file_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()> {
        unsafe { (**self).map_file_at(addr, len, prot, flags, offset, fd) }
    }

    #[inline]
    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<()> {
        unsafe { (**self).map_zero_at(addr, len, prot, flags) }
    }

    #[inline]
    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        unsafe { (**self).munmap(addr, len) }
    }

    #[inline]
    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()> {
        unsafe { (**self).madvise(addr, len, behavior) }
    }

    #[inline]
    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        unsafe { (**self).mprotect(addr, len, prot) }
    }
}
