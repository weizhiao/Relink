use super::{TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsTpOffset};
#[cfg(feature = "tls")]
use crate::observer::TlsDescValue;
use crate::{Result, TlsError, memory::VmAddr, relocation::RelocationArch};

/// A trait for resolving TLS (Thread Local Storage) information.
///
/// Implement this trait to provide custom TLS module IDs and thread pointer offsets.
/// This is essential for supporting TLS in environments with custom thread management,
/// such as operating system kernels or bare-metal systems.
pub trait TlsResolver<Arch: RelocationArch>: 'static {
    /// Whether this resolver should override `__tls_get_addr` symbol bindings.
    const OVERRIDE_TLS_GET_ADDR: bool = false;

    /// Registers a module with dynamic TLS and returns the allocated module ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the module ID cannot be allocated.
    fn register(tls_info: &TlsInfo) -> Result<TlsModuleId>;

    /// Registers a module with static TLS, returning the module ID and its thread pointer offset.
    ///
    /// # Errors
    ///
    /// Returns an error if space cannot be allocated in the static TLS area.
    fn register_static(tls_info: &TlsInfo) -> Result<(TlsModuleId, TlsTpOffset)>;

    /// Records an existing static TLS module and returns its allocated module ID.
    ///
    /// This is used when the TLS block is already set up and its offset from the thread
    /// pointer is known.
    fn add_static_tls(tls_info: &TlsInfo, offset: TlsTpOffset) -> Result<TlsModuleId>;

    /// Initializes a TLS module from a source that can provide the final
    /// relocated template on demand.
    ///
    /// TLS layout may be assigned before dynamic relocations have been applied.
    /// This hook is called once the template bytes are ready for future TLS block
    /// initialization. Static resolvers may also copy the template into the current
    /// thread's static TLS area.
    fn init_tls(
        source: TlsImageSource,
        mod_id: TlsModuleId,
        offset: Option<TlsTpOffset>,
    ) -> Result<()>;

    /// Releases resources associated with the given module ID.
    fn unregister(mod_id: TlsModuleId);

    /// Returns the target-visible `__tls_get_addr` entry point.
    ///
    /// Native same-process resolvers can return a host function pointer. Remote
    /// or guest runtimes should return an address inside the target runtime.
    fn bind_tls_get_addr() -> Result<VmAddr>;

    /// Resolves the current thread's host-visible address for a TLS variable.
    ///
    /// This is used by host APIs such as symbol lookup. Unlike
    /// [`bind_tls_get_addr`](Self::bind_tls_get_addr), the returned address must
    /// be meaningful to the caller in this process.
    fn resolve_tls_addr(ti: TlsIndex) -> Result<VmAddr>;

    /// Returns the target-visible TLSDESC binding for a static TLS access.
    #[cfg(feature = "tls")]
    #[inline]
    fn bind_static_tlsdesc(_tpoff: usize) -> Result<TlsDescValue> {
        Err(TlsError::ResolverUnsupported.into())
    }

    /// Returns the target-visible TLSDESC binding for a dynamic TLS access.
    #[cfg(feature = "tls")]
    #[inline]
    fn bind_dynamic_tlsdesc(_ti: TlsIndex) -> Result<TlsDescValue> {
        Err(TlsError::ResolverUnsupported.into())
    }
}

impl<Arch: RelocationArch> TlsResolver<Arch> for () {
    fn register(_tls_info: &TlsInfo) -> Result<TlsModuleId> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn register_static(_tls_info: &TlsInfo) -> Result<(TlsModuleId, TlsTpOffset)> {
        Err(TlsError::StaticResolverUnsupported.into())
    }

    fn add_static_tls(_tls_info: &TlsInfo, _offset: TlsTpOffset) -> Result<TlsModuleId> {
        Err(TlsError::StaticResolverUnsupported.into())
    }

    fn init_tls(
        _source: TlsImageSource,
        _mod_id: TlsModuleId,
        _offset: Option<TlsTpOffset>,
    ) -> Result<()> {
        Err(TlsError::StaticResolverUnsupported.into())
    }

    fn unregister(_mod_id: TlsModuleId) {
        // No-op for unit resolver as it doesn't maintain any state
    }

    fn bind_tls_get_addr() -> Result<VmAddr> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn resolve_tls_addr(_ti: TlsIndex) -> Result<VmAddr> {
        Err(TlsError::ResolverUnsupported.into())
    }
}
