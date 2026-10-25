use crate::{
    MmapError, Result,
    memory::{HostRegion, MappedRegion, VmAddr, VmOffset},
    os::{MapFlags, Mmap, ProtFlags, SpaceInit, SpaceLayout},
};

pub(super) use super::read_exact_at;

cfg_if::cfg_if! {
    if #[cfg(feature = "use-syscall")] {
        mod syscall;

        pub use syscall::DefaultMmap;
        pub(crate) use syscall::{
            RawFile, current_thread_id, get_thread_local_ptr, getauxval, path_is_dir,
            register_thread_destructor,
        };
    } else {
        mod libc;

        pub use libc::DefaultMmap;
        pub(crate) use libc::{
            RawFile, current_thread_id, get_thread_local_ptr, getauxval, path_is_dir,
            register_thread_destructor,
        };
    }
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
            mapper.map(
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
        mapper.map(
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
                    mapper.map(
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
