#[inline]
#[allow(dead_code)]
fn read_exact_at(
    mut bytes: &mut [u8],
    mut offset: usize,
    mut read_some: impl FnMut(&mut [u8], usize) -> crate::Result<usize>,
) -> crate::Result<()> {
    while !bytes.is_empty() {
        let bytes_to_read = bytes.len();
        let size = read_some(bytes, offset)?;
        if size == 0 {
            return Err(crate::IoError::FailedToFillBuffer.into());
        }
        debug_assert!(size <= bytes_to_read);
        if size > bytes_to_read {
            return Err(crate::IoError::ReadOutOfBounds(alloc::boxed::Box::new(
                crate::ReadBoundsError::new(offset, size, usize::MAX),
            ))
            .into());
        }
        offset =
            offset.checked_add(size).ok_or_else(|| {
                crate::IoError::ReadOutOfBounds(alloc::boxed::Box::new(
                    crate::ReadBoundsError::new(offset, bytes_to_read, usize::MAX),
                ))
            })?;
        bytes = &mut bytes[size..];
    }
    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod windows;

        pub use windows::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use windows::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use windows::{RawFile, virtual_free};
    } else if #[cfg(feature = "use-syscall")] {
        mod linux_syscall;

        pub use linux_syscall::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use linux_syscall::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        #[allow(unused_imports)]
        pub(crate) use linux_syscall::getauxval;
        pub(crate) use linux_syscall::RawFile;
    } else if #[cfg(all(any(target_os = "linux", target_os = "android"), feature = "libc"))] {
        mod linux_libc;

        pub use linux_libc::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use linux_libc::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        #[allow(unused_imports)]
        pub(crate) use linux_libc::getauxval;
        pub(crate) use linux_libc::RawFile;
    } else {
        mod baremetal;

        pub use baremetal::DefaultMmap;
        #[cfg(feature = "tls")]
        pub(crate) use baremetal::{current_thread_id, get_thread_local_ptr, register_thread_destructor};
        pub(crate) use baremetal::RawFile;
    }
}
