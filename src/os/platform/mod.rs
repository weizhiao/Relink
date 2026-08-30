use crate::{IoError, ReadBoundsError, Result};
use alloc::boxed::Box;

#[inline]
#[allow(dead_code)]
fn read_exact_at(
    mut bytes: &mut [u8],
    mut offset: usize,
    mut read_some: impl FnMut(&mut [u8], usize) -> Result<usize>,
) -> Result<()> {
    while !bytes.is_empty() {
        let bytes_to_read = bytes.len();
        let size = read_some(bytes, offset)?;
        if size == 0 {
            return Err(IoError::FailedToFillBuffer.into());
        }
        debug_assert!(size <= bytes_to_read);
        if size > bytes_to_read {
            return Err(IoError::ReadOutOfBounds(Box::new(ReadBoundsError::new(
                offset,
                size,
                usize::MAX,
            )))
            .into());
        }
        offset = offset.checked_add(size).ok_or_else(|| {
            IoError::ReadOutOfBounds(Box::new(ReadBoundsError::new(
                offset,
                bytes_to_read,
                usize::MAX,
            )))
        })?;
        bytes = &mut bytes[size..];
    }
    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod windows;

        pub use windows::DefaultMmap;
        pub(crate) use windows::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use windows::{RawFile, path_is_dir, virtual_free};
    } else if #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc"),
    ))] {
        mod linux;

        pub use linux::DefaultMmap;
        pub(crate) use linux::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        #[allow(unused_imports)]
        pub(crate) use linux::getauxval;
        pub(crate) use linux::{RawFile, path_is_dir};
    } else {
        mod baremetal;

        pub use super::mmap::AllocMmap as DefaultMmap;
        pub(crate) use baremetal::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use baremetal::{RawFile, path_is_dir};
    }
}
