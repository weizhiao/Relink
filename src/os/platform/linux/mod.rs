use crate::{
    MmapError, Result,
    input::Path,
    memory::{HostRegion, MappedRegion, VmAddr, VmOffset},
    os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags, SpaceInit, SpaceLayout},
    sync::OnceCell,
};

pub(super) use super::read_exact_at;

cfg_if::cfg_if! {
    if #[cfg(feature = "use-syscall")] {
        mod syscall;

        use self::syscall as backend;
    } else {
        mod libc;

        use self::libc as backend;
    }
}

pub(crate) use backend::{RawFile, getauxval, path_is_dir};

/// Default Linux mapping backend.
#[derive(Clone, Copy, Default)]
pub struct DefaultMmap;

impl DefaultMmap {
    /// Creates a mapper using the configured Linux backend.
    pub const fn new() -> Self {
        Self
    }
}

impl Mmap for DefaultMmap {
    type Region = HostRegion;

    #[cfg(not(feature = "use-syscall"))]
    fn page_size(&self) -> PageSize {
        backend::page_size()
    }

    fn thp_page_size(&self) -> Option<PageSize> {
        thp_page_size()
    }

    unsafe fn create_space(
        &self,
        layout: SpaceLayout,
        prot: ProtFlags,
        init: SpaceInit,
    ) -> Result<MappedRegion<Self::Region>> {
        unsafe { create_space(self, layout, prot, init) }
    }

    unsafe fn alias_space(&self, addr: VmAddr, len: usize) -> Result<MappedRegion<Self::Region>> {
        // SAFETY: the caller guarantees the existing mapping remains valid.
        Ok(unsafe { MappedRegion::local_alias(addr.as_mut_ptr(), len, *self) })
    }

    unsafe fn map_file_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
        fd: isize,
    ) -> Result<()> {
        unsafe { backend::map(addr, len, prot, flags, fd, offset) }
            .map(|_| ())
            .map_err(|code| MmapError::MmapFailed { code }.into())
    }

    unsafe fn map_zero_at(
        &self,
        addr: VmAddr,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<()> {
        unsafe { backend::map(addr, len, prot, flags | MapFlags::MAP_ANONYMOUS, -1, 0) }
            .map(|_| ())
            .map_err(|code| MmapError::MmapAnonymousFailed { code }.into())
    }

    unsafe fn munmap(&self, addr: VmAddr, len: usize) -> Result<()> {
        unsafe { backend::unmap(addr, len) }
    }

    unsafe fn madvise(&self, addr: VmAddr, len: usize, behavior: MadviseAdvice) -> Result<()> {
        unsafe { backend::advise(addr, len, behavior) }
    }

    unsafe fn mprotect(&self, addr: VmAddr, len: usize, prot: ProtFlags) -> Result<()> {
        unsafe { backend::protect(addr, len, prot) }
    }
}

fn thp_page_size() -> Option<PageSize> {
    static SIZE: OnceCell<Option<PageSize>> = OnceCell::new();
    *SIZE.get_or_init(|| {
        let file = RawFile::from_path(Path::new(
            "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
        ))
        .ok()?;
        let mut bytes = [0u8; 32];
        let len = file.read_some(&mut bytes, 0).ok()?;
        let size = core::str::from_utf8(&bytes[..len])
            .ok()?
            .strip_suffix('\n')?
            .parse()
            .ok()?;
        PageSize::new(size)
    })
}

// Both Linux backends use the same reservation and alignment rules.
unsafe fn create_space(
    mapper: &DefaultMmap,
    layout: SpaceLayout,
    prot: ProtFlags,
    init: SpaceInit,
) -> Result<MappedRegion<HostRegion>> {
    let (flags, fd, offset) = match init {
        SpaceInit::Reserve | SpaceInit::Zeroed => {
            (MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS, -1, 0)
        }
        SpaceInit::File { fd, offset } => (MapFlags::MAP_PRIVATE, fd, offset),
    };
    let page_size = mapper.page_size().bytes();
    if layout.align == page_size {
        let start = unsafe {
            backend::map(
                layout.addr.unwrap_or(VmAddr::null()),
                layout.len,
                prot,
                flags,
                fd,
                offset,
            )
        }
        .map_err(|code| match init {
            SpaceInit::File { .. } => MmapError::MmapFailed { code },
            SpaceInit::Reserve | SpaceInit::Zeroed => MmapError::MmapAnonymousFailed { code },
        })?;
        // SAFETY: the successful mapping transfers ownership of this range.
        return Ok(unsafe {
            MappedRegion::local(
                start.as_mut_ptr(),
                layout.len,
                start.as_mut_ptr(),
                layout.len,
                *mapper,
            )
        });
    }

    let reserved_len = layout
        .len
        .checked_add(layout.align - page_size)
        .ok_or(MmapError::InvalidMappedRegionRange)?;
    let owned_start = unsafe {
        backend::map(
            layout.addr.unwrap_or(VmAddr::null()),
            reserved_len,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .map_err(|code| MmapError::MmapAnonymousFailed { code })?;
    let mut owned_len = reserved_len;
    let result = (|| -> Result<VmAddr> {
        let prefix = layout.padding_at(owned_start);
        let start = owned_start + VmOffset::new(prefix);
        let suffix = owned_len - prefix - layout.len;
        let end = start + VmOffset::new(layout.len);
        match init {
            SpaceInit::File { .. } => {
                // MAP_FIXED stays inside the range reserved above.
                let _ = unsafe {
                    backend::map(
                        start,
                        layout.len,
                        prot,
                        flags | MapFlags::MAP_FIXED,
                        fd,
                        offset,
                    )
                }
                .map_err(|code| MmapError::MmapFailed { code })?;
            }
            SpaceInit::Zeroed if prot.bits() != ProtFlags::PROT_NONE.bits() => {
                // The anonymous reservation already supplies zero pages.
                unsafe { mapper.mprotect(start, layout.len, prot) }?;
            }
            SpaceInit::Reserve | SpaceInit::Zeroed => {}
        }

        // If trimming the prefix fails, cleanup must exclude the released suffix.
        if suffix != 0 {
            unsafe { mapper.munmap(end, suffix) }?;
            owned_len -= suffix;
        }
        if prefix != 0 {
            unsafe { mapper.munmap(owned_start, prefix) }?;
        }
        Ok(start)
    })();
    match result {
        Ok(start) => {
            // SAFETY: only the selected page-rounded range remains owned.
            Ok(unsafe {
                MappedRegion::local(
                    start.as_mut_ptr(),
                    layout.len,
                    start.as_mut_ptr(),
                    layout.len,
                    *mapper,
                )
            })
        }
        Err(error) => {
            let _ = unsafe { mapper.munmap(owned_start, owned_len) };
            Err(error)
        }
    }
}
