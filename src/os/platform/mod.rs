use crate::{IoError, Result};

/// Reads a validated file range using a platform reader that returns at most
/// the supplied buffer length.
#[inline]
#[allow(dead_code)]
fn read_exact_at(
    mut bytes: &mut [u8],
    mut offset: usize,
    mut read_some: impl FnMut(&mut [u8], usize) -> Result<usize>,
) -> Result<()> {
    while !bytes.is_empty() {
        let size = read_some(bytes, offset)?;
        if size == 0 {
            return Err(IoError::FailedToFillBuffer.into());
        }
        offset += size;
        bytes = &mut bytes[size..];
    }
    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod windows;

        pub use windows::DefaultMmap;
        pub(crate) use windows::{RawFile, path_is_dir};
    } else if #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "std"),
    ))] {
        mod linux;

        pub use linux::DefaultMmap;
        #[allow(unused_imports)]
        pub(crate) use linux::getauxval;
        pub(crate) use linux::{RawFile, path_is_dir};
    } else {
        mod baremetal;

        pub use super::mmap::AllocMmap as DefaultMmap;
        pub(crate) use baremetal::{RawFile, path_is_dir};
    }
}
