use super::{ModuleTls, TlsDescValue, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsRequest};
use crate::{Result, TlsError, memory::VmAddr, relocation::RelocationArch};

/// A trait for resolving TLS (Thread Local Storage) information.
///
/// Implement this trait to provide custom TLS module IDs and thread pointer offsets.
/// This is essential for supporting TLS in environments with custom thread management,
/// such as operating system kernels or bare-metal systems.
pub trait TlsResolver<Arch: RelocationArch>: 'static {
    /// Whether this resolver should override `__tls_get_addr` symbol bindings.
    const OVERRIDE_TLS_GET_ADDR: bool = false;

    /// Registers a TLS module using the requested placement.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested placement cannot be satisfied.
    fn register(info: TlsInfo, request: TlsRequest) -> Result<ModuleTls>;

    /// Initializes a TLS module from a source that can provide the final
    /// relocated template on demand.
    ///
    /// TLS layout may be assigned before dynamic relocations have been applied.
    /// This hook is called once the template bytes are ready for future TLS block
    /// initialization. Static resolvers may also copy the template into the current
    /// thread's static TLS area.
    fn init_tls(source: TlsImageSource, mod_id: TlsModuleId) -> Result<()>;

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
    #[inline]
    fn bind_static_tlsdesc(_tpoff: usize) -> Result<TlsDescValue> {
        Err(TlsError::ResolverUnsupported.into())
    }

    /// Returns the target-visible TLSDESC binding for a dynamic TLS access.
    #[inline]
    fn bind_dynamic_tlsdesc(_ti: TlsIndex) -> Result<TlsDescValue> {
        Err(TlsError::ResolverUnsupported.into())
    }

    /// Returns the target-visible TLSDESC binding for an undefined weak TLS symbol.
    #[inline]
    fn bind_undefweak_tlsdesc(_addend: usize) -> Result<TlsDescValue> {
        Err(TlsError::ResolverUnsupported.into())
    }
}

impl<Arch: RelocationArch> TlsResolver<Arch> for () {
    fn register(_info: TlsInfo, _request: TlsRequest) -> Result<ModuleTls> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn init_tls(_source: TlsImageSource, _mod_id: TlsModuleId) -> Result<()> {
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
