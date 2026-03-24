use super::{TlsIndex, TlsInfo};
use crate::{Result, tls_resolver_unsupported_error, tls_static_resolver_unsupported_error};

const TLS_GET_ADDR_DISABLED_MESSAGE: &str = if cfg!(feature = "tls") {
    "tls_get_addr called on unit TlsResolver which does not support TLS. Use `with_default_tls_resolver()` to enable TLS support."
} else {
    "tls_get_addr called without compiled-in TLS support. Enable the `tls` cargo feature."
};

/// A trait for resolving TLS (Thread Local Storage) information.
///
/// Implement this trait to provide custom TLS module IDs and thread pointer offsets.
/// This is essential for supporting TLS in environments with custom thread management,
/// such as operating system kernels or bare-metal systems.
pub trait TlsResolver {
    /// Registers a module with dynamic TLS and returns the allocated module ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the module ID cannot be allocated.
    fn register(tls_info: &TlsInfo) -> Result<usize>;

    /// Registers a module with static TLS, returning the module ID and its thread pointer offset.
    ///
    /// # Errors
    ///
    /// Returns an error if space cannot be allocated in the static TLS area.
    fn register_static(tls_info: &TlsInfo) -> Result<(usize, isize)>;

    /// Records an existing static TLS module and returns its allocated module ID.
    ///
    /// This is used when the TLS block is already set up and its offset from the thread
    /// pointer is known.
    fn add_static_tls(tls_info: &TlsInfo, offset: isize) -> Result<usize>;

    /// Releases resources associated with the given module ID.
    fn unregister(mod_id: usize);

    /// Returns the address of a thread-local variable for the given index.
    ///
    /// This is typically called by architecture-specific TLS relocation handlers.
    extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8;
}

impl TlsResolver for () {
    fn register(_tls_info: &TlsInfo) -> Result<usize> {
        Err(tls_resolver_unsupported_error())
    }

    fn register_static(_tls_info: &TlsInfo) -> Result<(usize, isize)> {
        Err(tls_static_resolver_unsupported_error())
    }

    fn add_static_tls(_tls_info: &TlsInfo, _offset: isize) -> Result<usize> {
        Err(tls_static_resolver_unsupported_error())
    }

    fn unregister(_mod_id: usize) {
        // No-op for unit resolver as it doesn't maintain any state
    }

    extern "C" fn tls_get_addr(_ti: *const TlsIndex) -> *mut u8 {
        panic!("{TLS_GET_ADDR_DISABLED_MESSAGE}");
    }
}
