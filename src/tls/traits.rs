use crate::Result;
use super::{TlsIndex, TlsInfo};

/// A trait for resolving TLS (Thread Local Storage) information.
///
/// Implement this trait to provide custom TLS module IDs and thread pointer offsets.
/// This is essential for supporting TLS in environments with custom thread management.
pub trait TlsResolver {
    /// Register a module with dynamic TLS.
    ///
    /// # Arguments
    /// * `tls_info` - TLS metadata and template for the ELF object.
    ///
    /// # Returns
    /// * `Result<usize>` - The module ID.
    fn register(tls_info: &TlsInfo) -> Result<usize>;

    /// Register a module with static TLS.
    ///
    /// The resolver should choose a suitable offset for the TLS block.
    ///
    /// # Arguments
    /// * `tls_info` - TLS metadata and template for the ELF object.
    ///
    /// # Returns
    /// * `Result<(usize, isize)>` - The module ID and its thread pointer offset.
    fn register_static(tls_info: &TlsInfo) -> Result<(usize, isize)>;

    /// Record an existing static TLS module.
    ///
    /// This is used when the TLS block is already set up (e.g., by the OS or a
    /// bootloader) and its offset from the thread pointer is known. The
    /// resolver just records this metadata and assigns a module ID.
    ///
    /// # Arguments
    /// * `tls_info` - TLS metadata and template for the ELF object.
    /// * `offset` - Static TLS offset from thread pointer.
    ///
    /// # Returns
    /// * `Result<usize>` - The module ID.
    fn add_static_tls(tls_info: &TlsInfo, offset: isize) -> Result<usize>;

    /// Called when the module is unloaded.
    /// Implementations should release any resources associated with this module.
    fn unregister(mod_id: usize);

    /// Returns the address of a thread-local variable.
    extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8;
}
