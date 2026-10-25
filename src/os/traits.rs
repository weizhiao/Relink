use super::{MadviseAdvice, MapFlags, PageSize, ProtFlags};
use crate::memory::{MappedRegion, RegionAccess, VmAddr};
use crate::{Result, input::FileBacking};
use alloc::sync::Arc;

/// Address preference, size, and alignment of a newly created mapping.
#[derive(Clone, Copy, Debug)]
pub struct SpaceLayout {
    /// Optional page-aligned address. Native backends treat it as a placement
    /// hint; allocator and fixed backends use it to select caller-owned storage.
    pub addr: Option<VmAddr>,
    /// Nonzero number of bytes in the returned region, a multiple of the backend's page size.
    pub len: usize,
    /// Power-of-two address alignment, at least the backend's page size.
    pub align: usize,
    /// Page-aligned address offset: the region's address must be congruent to
    /// this value modulo `align`. Zero requests an aligned region start.
    pub offset: usize,
}

impl SpaceLayout {
    #[inline]
    pub(crate) fn is_aligned(self, addr: VmAddr) -> bool {
        self.padding_at(addr) == 0
    }

    /// Returns the leading padding needed to satisfy this layout's alignment.
    /// The caller must reserve enough space for the padding and region.
    #[inline]
    pub(crate) fn padding_at(self, addr: VmAddr) -> usize {
        self.offset.wrapping_sub(addr.get()) & (self.align - 1)
    }
}

/// Initial contents of a newly created address range.
#[derive(Clone, Copy, Debug)]
pub enum SpaceInit {
    /// Reserves space for later file or zero-page mappings. Its contents and
    /// access permissions are not guaranteed until the range is populated.
    Reserve,
    /// Clears the entire range, including caller-owned storage, and applies the
    /// requested permissions.
    Zeroed,
    /// Creates a private file mapping with the requested permissions.
    File {
        /// Borrowed readable file descriptor or platform handle.
        fd: isize,
        /// Page-aligned starting offset in the file.
        offset: usize,
    },
}

/// Creates and manages memory mappings for loaded images.
///
/// [`Self::create_space`] returns an owned mapping. File and zero-page operations
/// fill subranges without taking ownership. Implementations must support
/// concurrent calls and report mapping failures.
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

    /// Selects direct mapping (`Some`) or reading and copying (`None`, the default).
    ///
    /// An accepted range must contain the same bytes as the input. This query does
    /// not map memory or take ownership of the file handle. Invalid descriptions
    /// return errors; later mapping failures do not fall back to copying.
    #[inline]
    fn file_backing(&self, _backing: FileBacking) -> Result<Option<FileBacking>> {
        Ok(None)
    }

    /// Creates an owned address range with the requested size and alignment,
    /// using `layout.addr` as the backend's placement hint or storage address.
    ///
    /// The returned region has `layout.len` bytes and its address is congruent to
    /// `layout.offset` modulo `layout.align`, for every initialization mode.
    /// Fixed or caller-owned storage must satisfy this constraint before any
    /// initialization; otherwise the backend returns an error.
    ///
    /// [`SpaceInit::Zeroed`] initializes the entire range to zero, while
    /// [`SpaceInit::File`] maps file contents. Both use `prot`; callers writing
    /// into the range must request writable protection. [`SpaceInit::Reserve`]
    /// only requires reservation; populate file or zero pages before access.
    ///
    /// If file initialization is unsupported, return
    /// [`crate::error::MmapError::FileMappingUnsupported`] without creating a mapping or
    /// modifying caller-owned storage. The caller may then reserve space and use
    /// [`Self::map_file_at`], which is a separate backend capability. Other mapping
    /// errors must be propagated rather than treated as unsupported initialization.
    ///
    /// # Safety
    /// `layout.len` must be nonzero and a multiple of the backend's page size.
    /// `layout.addr`, when supplied, and `layout.offset` must be page-aligned.
    /// `layout.align` must be a power of two at least as large as the backend's
    /// page size. Caller-owned storage must remain valid and be exclusively
    /// available for initialization and loading.
    ///
    /// For file initialization, `offset` must be page-aligned and `fd` readable.
    /// The mapping may extend past EOF: replace whole pages beyond EOF before
    /// accessing them, and apply each segment's final permissions before exposing
    /// the image. Unused gaps may remain mapped but must be inaccessible. The
    /// partial EOF page follows the backend's file-tail rules.
    unsafe fn create_space(
        &self,
        layout: SpaceLayout,
        prot: ProtFlags,
        init: SpaceInit,
    ) -> Result<MappedRegion<Self::Region>>;

    /// Borrows an existing mapping without changing its contents or unmapping it on drop.
    /// The view should support protection changes when the backend allows them.
    ///
    /// # Safety
    /// `addr..addr + len` must remain mapped for the returned region's lifetime.
    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>>;

    /// Maps file contents into a subrange of an owned mapping created by this backend.
    /// The backend must prepare the subrange, splitting reservations if needed.
    /// Unsupported operations must return an error.
    ///
    /// # Safety
    /// `addr..addr + len` must be within a region created by this mapper.
    /// `fd` and `offset` must identify a valid readable file range of `len` bytes.
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
    /// The mapped range is owned by the surrounding space created with this
    /// backend. The backend must prepare the target subrange,
    /// including splitting address reservations when the platform requires it.
    ///
    /// # Safety
    /// `addr..addr + len` must be inside a region previously created by this
    /// mapper and must not overlap incompatible existing mappings.
    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<()>;

    /// Releases an owned mapping created by this backend.
    ///
    /// A region that owns its storage directly can release it on drop instead.
    /// Such a backend may reject this operation when the address and length do
    /// not provide enough information to release that storage.
    ///
    /// # Safety
    /// `addr` must be page-aligned, and `addr` and `len` must describe an owned
    /// range that this backend supports releasing independently. Unless the
    /// backend supports partial unmapping, they must match the original mapping.
    /// No code may access the released range after it is unmapped.
    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()>;

    /// Applies memory-usage advice to a mapped range.
    /// Unsupported advice may return an error.
    ///
    /// # Safety
    /// `addr` must be page-aligned. The caller must account for the effects of
    /// `behavior`, including advice that discards or frees memory contents.
    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()>;

    /// Changes access permissions for `len` bytes, rounded up to a page boundary.
    /// Used, for example, to make RELRO memory read-only after relocation.
    ///
    /// # Safety
    /// `addr` must be page-aligned and identify a valid mapping. Ensure all users
    /// of the range permit the change; no code may execute there when execute
    /// permission is removed.
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
    fn file_backing(&self, backing: FileBacking) -> Result<Option<FileBacking>> {
        (**self).file_backing(backing)
    }

    #[inline]
    unsafe fn create_space(
        &self,
        layout: SpaceLayout,
        prot: ProtFlags,
        init: SpaceInit,
    ) -> Result<MappedRegion<Self::Region>> {
        unsafe { (**self).create_space(layout, prot, init) }
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
