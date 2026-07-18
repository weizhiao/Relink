use super::{
    ModuleTls, TlsDescBinding, TlsDescRequest, TlsImageSource, TlsInfo, TlsModuleId, TlsRequest,
};
use crate::{Result, TlsError, memory::VmAddr, relocation::RelocationArch};

/// A trait for resolving TLS (Thread Local Storage) information.
///
/// Implement this trait to provide custom TLS module IDs and thread pointer offsets.
/// This is essential for supporting TLS in environments with custom thread management,
/// such as operating system kernels or bare-metal systems.
///
/// A loader retains a cloneable resolver handle, and every module
/// produced by that loader uses the same instance for registration, relocation,
/// address lookup, and cleanup. Implementations may therefore keep their TLS
/// registry and runtime bindings directly in the resolver.
pub trait TlsResolver<Arch: RelocationArch>: Clone + Send + Sync + 'static {
    /// Whether this resolver should override `__tls_get_addr` symbol bindings.
    const OVERRIDE_TLS_GET_ADDR: bool = false;

    /// Registers a TLS module using the requested placement.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested placement cannot be satisfied.
    fn register(&self, info: TlsInfo, request: TlsRequest) -> Result<ModuleTls>;

    /// Publishes the final relocated template for a registered TLS module.
    ///
    /// TLS layout may be assigned before dynamic relocations have been applied.
    /// This hook is called once the template bytes are ready for future TLS block
    /// initialization. The resolver decides when and where per-thread storage is
    /// instantiated.
    fn publish(&self, source: TlsImageSource, mod_id: TlsModuleId) -> Result<()>;

    /// Releases resources associated with the given module ID.
    fn unregister(&self, mod_id: TlsModuleId);

    /// Returns the target-visible `__tls_get_addr` entry point.
    ///
    /// Native same-process resolvers can return a host function pointer. Remote
    /// or guest runtimes should return an address inside the target runtime.
    fn bind_tls_get_addr(&self) -> Result<VmAddr>;

    /// Returns a target-visible TLSDESC binding.
    #[inline]
    fn bind_tlsdesc(&self, _request: TlsDescRequest) -> Result<TlsDescBinding> {
        Err(TlsError::ResolverUnsupported.into())
    }
}

impl<Arch: RelocationArch> TlsResolver<Arch> for () {
    fn register(&self, _info: TlsInfo, _request: TlsRequest) -> Result<ModuleTls> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn publish(&self, _source: TlsImageSource, _mod_id: TlsModuleId) -> Result<()> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn unregister(&self, _mod_id: TlsModuleId) {
        // No-op for unit resolver as it doesn't maintain any state
    }

    fn bind_tls_get_addr(&self) -> Result<VmAddr> {
        Err(TlsError::ResolverUnsupported.into())
    }
}
