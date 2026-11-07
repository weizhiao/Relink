use super::{
    TlsContext, TlsDescBinding, TlsDescRequest, TlsDescSetup, TlsIndex, TlsInfo, TlsModuleId,
    TlsRegistration, TlsRequest, TlsTemplate,
};
use crate::{
    Result, TlsError,
    arch::{tlsdesc_resolver_dynamic, tlsdesc_resolver_static, tlsdesc_resolver_undefweak},
    memory::VmAddr,
    relocation::RelocationArch,
};
use alloc::boxed::Box;
use core::ptr::NonNull;

/// Provides per-thread storage for a registered TLS module.
///
/// The registry assigns IDs and metadata; the provider publishes templates and
/// resolves addresses. Callbacks and destruction may reenter the loader and run
/// without registry locks or mutable thread-state borrows held by the caller.
///
/// # Safety
/// Returned pointers must address the registered block in the calling thread and
/// remain valid until module or thread teardown. Resolvers may cache that block's
/// base for this lifetime without calling the provider again. Retain the runtime
/// resources needed by each operation and support concurrent calls from different threads.
/// Host storage must retain its original module and must not be freed or
/// reinitialized by the importing runtime. Publish managed templates before
/// exposing their storage. Do not retain the image owning this registration:
/// that would create an ownership cycle.
pub unsafe trait TlsProvider: Send + Sync + 'static {
    /// Publishes a relocated initialization template. Providers for existing
    /// storage normally retain the default rejection of publication.
    /// Call at most once per registration; repeated publication may panic.
    ///
    /// # Safety
    /// `context` must be the metadata assigned when this provider was registered.
    /// The entry may have since been removed; retained provider resources must
    /// remain usable, or the operation must report unavailable storage.
    unsafe fn publish(&self, _context: &TlsContext, _source: TlsTemplate) -> Result<()> {
        Err(TlsError::ModuleMismatch.into())
    }

    /// Returns the current thread's block base, allocating storage if needed.
    /// The returned base has no ABI-specific DTV bias; providers translate it internally.
    ///
    /// # Safety
    /// `context` must be the metadata assigned when this provider was registered.
    /// The entry may have since been removed; retained provider resources must
    /// remain usable, or the operation must report unavailable storage.
    unsafe fn get_or_init(&self, context: &TlsContext) -> Result<NonNull<u8>>;

    /// Queries an existing block without allocating a TLS block.
    /// The storage backend may initialize thread-local lookup bookkeeping.
    /// `None` also means that querying existing storage is unsupported.
    ///
    /// # Safety
    /// `context` must be the metadata assigned when this provider was registered.
    /// The entry may have since been removed; retained provider resources must
    /// remain usable, or the operation must report unavailable storage.
    unsafe fn get(&self, context: &TlsContext) -> Option<NonNull<u8>>;
}

/// Registers TLS modules and supplies their runtime entry points.
///
/// Attach a resolver to a [`Domain`](crate::Domain) to use it for loading and
/// relocation. Clones must share the same runtime and module-ID namespace;
/// that runtime must remain fixed for the resolver's lifetime.
pub trait TlsResolver<Arch: RelocationArch>: Clone + Send + Sync + 'static {
    /// Whether this resolver should override `__tls_get_addr` symbol bindings.
    const OVERRIDE_TLS_GET_ADDR: bool = false;

    /// Registers a TLS module with the requested placement and automatic cleanup.
    ///
    /// The returned guard owns cleanup; drop it to unregister the module.
    /// The registration must use this resolver's namespace and
    /// [`Self::bind_tls_get_addr`] entry. On error, no new registration may remain.
    ///
    /// # Errors
    /// Returns an error if the requested placement cannot be satisfied.
    fn register(&self, info: TlsInfo, request: TlsRequest) -> Result<TlsRegistration>;

    /// Publishes relocated bytes used to initialize per-thread TLS blocks.
    ///
    /// `mod_id` must belong to this resolver, and its registration must remain alive
    /// throughout the call. Call at most once per registration; repetition may panic.
    fn publish(&self, source: TlsTemplate, mod_id: TlsModuleId) -> Result<()>;

    /// Returns the `__tls_get_addr` entry address in the target runtime.
    ///
    /// The entry and its module-ID namespace must remain fixed across clones.
    /// Resolvers sharing an entry must share that namespace. Do not reuse IDs while
    /// code or descriptors can reference them; registration owners must retain the runtime.
    fn bind_tls_get_addr(&self) -> Result<VmAddr>;

    /// Creates a TLSDESC binding and state retained by the image using it.
    ///
    /// The default uses native ABI stubs; non-native runtimes must override it.
    /// A defined symbol must belong to this resolver's namespace. Its module and
    /// runtime must remain valid while the descriptor is in use.
    #[inline]
    fn bind_tlsdesc(&self, request: TlsDescRequest) -> Result<TlsDescSetup> {
        // The containing image owns these arguments. Module dependencies keep the
        // defining image alive; imported providers retain their original storage.
        #[repr(C)]
        struct DynamicArg {
            entry: usize,
            index: TlsIndex,
        }

        if !Arch::SUPPORTS_NATIVE_RUNTIME || Arch::TLSDESC.is_none() {
            return Err(TlsError::ResolverUnsupported.into());
        }
        match request {
            TlsDescRequest::Defined { module, offset } => {
                if let Some(tp_offset) = module.tp_offset() {
                    return Ok(TlsDescSetup::new(TlsDescBinding::new(
                        VmAddr::from_ptr(tlsdesc_resolver_static as *const ()),
                        VmAddr::new(offset)
                            .wrapping_add_signed(tp_offset.get())
                            .get(),
                    )));
                }
                let arg = Box::new(DynamicArg {
                    entry: module.entry().get(),
                    index: TlsIndex {
                        ti_module: module.mod_id(),
                        ti_offset: offset.wrapping_sub(Arch::TLS_DTV_OFFSET),
                    },
                });
                let ptr = VmAddr::from_ptr(arg.as_ref());
                Ok(TlsDescSetup::new(TlsDescBinding::new(
                    VmAddr::from_ptr(tlsdesc_resolver_dynamic as *const ()),
                    ptr.get(),
                ))
                .with_state(arg))
            }
            TlsDescRequest::UndefinedWeak { addend } => Ok(TlsDescSetup::new(TlsDescBinding::new(
                VmAddr::from_ptr(tlsdesc_resolver_undefweak as *const ()),
                addend,
            ))),
        }
    }
}

impl<Arch: RelocationArch> TlsResolver<Arch> for () {
    fn register(&self, _info: TlsInfo, _request: TlsRequest) -> Result<TlsRegistration> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn publish(&self, _source: TlsTemplate, _mod_id: TlsModuleId) -> Result<()> {
        Err(TlsError::ResolverUnsupported.into())
    }

    fn bind_tls_get_addr(&self) -> Result<VmAddr> {
        Err(TlsError::ResolverUnsupported.into())
    }
}
