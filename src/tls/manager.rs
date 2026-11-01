use super::dtv::{DtvLookup, ensure_supported, lookup_dtv, with_dtv};
use crate::{
    Result, TlsError,
    arch::{NativeArch, get_thread_pointer},
    memory::VmAddr,
    relocation::RelocationArch,
    sync::{AtomicUsize, OnceCell, Ordering},
    tls::{
        TlsContext, TlsIndex, TlsInfo, TlsModule, TlsModuleId, TlsOwner, TlsProvider,
        TlsRegistration, TlsRegistry, TlsRequest, TlsResolver, TlsTemplate, TlsTpOffset,
    },
};
use core::ptr::NonNull;
use spin::RwLock;

/// Global registry for all loaded modules' TLS metadata.
/// This allows any thread to look up how to initialize TLS for a specific module ID.
static MODULE_REGISTRY: RwLock<TlsRegistry> = RwLock::new(TlsRegistry::new());

#[inline]
fn with_registry<T>(f: impl FnOnce(&TlsRegistry) -> T) -> T {
    let registry = MODULE_REGISTRY.read();
    f(&registry)
}

#[inline]
fn with_registry_mut<T>(f: impl FnOnce(&mut TlsRegistry) -> T) -> T {
    let mut registry = MODULE_REGISTRY.write();
    let result = f(&mut registry);
    GLOBAL_GENERATION.store(registry.generation(), Ordering::Release);
    result
}

/// Global generation counter. Changes when registry membership changes.
/// DTVs use this to detect if they are stale and need updating.
static GLOBAL_GENERATION: AtomicUsize = AtomicUsize::new(0);

/// TLS resolver for code running in the current process.
/// Clones share the global registry; each thread has its own TLS blocks.
/// Managed dynamic blocks require `std`; other environments need a custom
/// resolver or provider for dynamic thread storage.
#[derive(Clone, Copy, Debug)]
pub struct DefaultTlsResolver;

impl DefaultTlsResolver {
    /// Creates a default TLS resolver handle.
    pub const fn new() -> Self {
        Self
    }

    /// Returns the current thread pointer.
    pub fn get_thread_pointer() -> *mut u8 {
        unsafe { get_thread_pointer() }
    }

    /// Returns the registered TLS segment metadata for a module.
    pub fn get_info(mod_id: TlsModuleId) -> Option<TlsInfo> {
        with_registry(|registry| registry.info(mod_id))
    }

    /// Registers a custom provider in the default runtime's namespace.
    /// The returned owner unregisters and releases the provider on drop.
    ///
    /// # Safety
    /// `info` must describe the provider's TLS block. If supplied, `tp_offset`
    /// must identify that block in every current and future thread. A pointer
    /// observed in one thread alone is not proof of static placement. The
    /// provider must support this runtime's namespace and thread storage.
    pub unsafe fn register_provider<P: TlsProvider>(
        &self,
        info: TlsInfo,
        tp_offset: Option<TlsTpOffset>,
        provider: P,
    ) -> Result<TlsRegistration> {
        let entry = self.bind_tls_get_addr()?;
        let owner = TlsOwner::new(provider);
        let module =
            with_registry_mut(|registry| unsafe { registry.register(info, tp_offset, &owner) })?;
        let mod_id = module.mod_id();
        // SAFETY: This guard is the only owner of the newly inserted entry.
        Ok(unsafe {
            TlsRegistration::new(TlsModule::new(module, entry), move || {
                unregister(mod_id);
            })
        })
    }

    /// Resolves the current thread's block, allocating managed or host TLS if needed.
    /// The raw pointer must not be used from another thread or after module/thread
    /// teardown. No reference or aliasing guarantee is implied.
    ///
    /// # Panics
    /// Panics if required managed thread storage cannot be installed or has
    /// already been destroyed during thread teardown, or if resolution reenters
    /// a managed thread storage update.
    pub fn get_ptr(mod_id: TlsModuleId) -> Option<*mut u8> {
        get_dynamic(mod_id)
            .or_else(|| resolve_slow(mod_id, 0).ok())
            .map(NonNull::as_ptr)
    }

    /// Queries an existing block without allocating a TLS block.
    /// With `std`, OS-backed TLS may initialize per-thread cache bookkeeping.
    pub fn get_ptr_if_allocated(mod_id: TlsModuleId) -> Option<*mut u8> {
        if let Some(base) = get_dynamic(mod_id) {
            return Some(base.as_ptr());
        }
        let entry = with_registry(|registry| registry.lookup(mod_id)).ok()?;
        entry.get().map(NonNull::as_ptr)
    }
}

impl Default for DefaultTlsResolver {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl TlsResolver<NativeArch> for DefaultTlsResolver {
    const OVERRIDE_TLS_GET_ADDR: bool = true;

    fn register(&self, info: TlsInfo, request: TlsRequest) -> Result<TlsRegistration> {
        let tp_offset = match request {
            TlsRequest::Dynamic => {
                ensure_supported()?;
                None
            }
            TlsRequest::Static(Some(offset)) => Some(offset),
            TlsRequest::Static(None) => return Err(TlsError::ResolverUnsupported.into()),
        };
        // SAFETY: ManagedTls uses this runtime's thread cache and placement.
        unsafe { self.register_provider(info, tp_offset, ManagedTls::new()) }
    }

    fn publish(&self, source: TlsTemplate, mod_id: TlsModuleId) -> Result<()> {
        let entry = with_registry(|registry| registry.lookup(mod_id))?;
        entry.publish(source)
    }

    fn bind_tls_get_addr(&self) -> Result<VmAddr> {
        Ok(VmAddr::from_ptr(tls_get_addr as *const ()))
    }
}

fn unregister(mod_id: TlsModuleId) {
    let owner = with_registry_mut(|registry| registry.unregister(mod_id));
    // A provider's destructor can call the host loader. Never drop it under a lock.
    drop(owner);
}

#[cold]
fn resolve_slow(mod_id: TlsModuleId, offset: usize) -> Result<NonNull<u8>> {
    let entry = with_registry(|registry| registry.lookup(mod_id))?;
    entry.resolve(offset)
}

fn static_address(offset: TlsTpOffset) -> Option<NonNull<u8>> {
    let tp = unsafe { get_thread_pointer() };
    NonNull::new(tp.wrapping_offset(offset.get()))
}

/// Managed storage tied to the default runtime's registry and thread cache.
/// Custom registries must use a provider tied to their own thread state.
pub(super) struct ManagedTls {
    image: OnceCell<TlsTemplate>,
}

impl ManagedTls {
    pub(super) const fn new() -> Self {
        Self {
            image: OnceCell::new(),
        }
    }
}

unsafe impl TlsProvider for ManagedTls {
    unsafe fn publish(&self, _context: &TlsContext, source: TlsTemplate) -> Result<()> {
        assert!(
            self.image.set(source).is_ok(),
            "TLS template must be published only once",
        );
        Ok(())
    }

    unsafe fn resolve(&self, context: &TlsContext, offset: usize) -> Result<NonNull<u8>> {
        let source = self.image.get().ok_or(TlsError::TemplateUnavailable)?;
        let binding = context.binding();
        let base = if let Some(tp_offset) = binding.tp_offset() {
            static_address(tp_offset).ok_or(TlsError::InvalidInfo)?
        } else {
            get_or_init_dynamic(context, source.as_ref())?
        };
        NonNull::new(base.as_ptr().wrapping_add(offset)).ok_or_else(|| TlsError::InvalidInfo.into())
    }

    unsafe fn get(&self, context: &TlsContext) -> Option<NonNull<u8>> {
        self.image.get()?;
        let binding = context.binding();
        if let Some(tp_offset) = binding.tp_offset() {
            static_address(tp_offset)
        } else {
            get_dynamic(binding.mod_id())
        }
    }
}

fn get_or_init_dynamic(context: &TlsContext, image: &[u8]) -> Result<NonNull<u8>> {
    let mod_id = context.binding().mod_id();
    with_dtv(|dtv| {
        if dtv.generation() == GLOBAL_GENERATION.load(Ordering::Acquire)
            && let Some(base) = dtv.get(mod_id)
        {
            return Ok(base);
        }
        // Synchronize and validate the full ID under the same registry read lock.
        // DTV cleanup frees only TLS blocks; it invokes no provider callbacks.
        let registered = with_registry(|registry| {
            dtv.sync(registry);
            registry.contains(mod_id)
        });
        if !registered {
            return Err(TlsError::InvalidModuleId { mod_id }.into());
        }
        dtv.get_or_init(mod_id, context.info(), image)
    })
}

#[inline]
fn get_dynamic(mod_id: TlsModuleId) -> Option<NonNull<u8>> {
    // Only managed dynamic blocks enter this DTV. Synchronization removes IDs
    // absent while the registry is read-locked; it does not pin modules afterward.
    // With an unchanged generation, a hit needs no registry lock or provider.
    let generation = GLOBAL_GENERATION.load(Ordering::Acquire);
    match lookup_dtv::<false>(mod_id, generation) {
        DtvLookup::Found(base) => Some(base),
        DtvLookup::Missing => None,
        DtvLookup::Stale => get_dynamic_slow(mod_id),
    }
}

#[cold]
fn get_dynamic_slow(mod_id: TlsModuleId) -> Option<NonNull<u8>> {
    with_dtv(|dtv| {
        with_registry(|registry| dtv.sync(registry));
        dtv.get(mod_id)
    })
}

// Each entry uses the ABI of loaded ELF code, including on Windows.
cfg_if::cfg_if! {
    if #[cfg(all(windows, target_arch = "x86_64"))] {
        extern "sysv64" fn tls_get_addr(index: *const TlsIndex) -> *mut u8 {
            resolve_index(unsafe { &*index })
        }
    } else if #[cfg(feature = "std")] {
        extern "C" fn tls_get_addr(index: *const TlsIndex) -> *mut u8 {
            let ti = unsafe { &*index };
            if let DtvLookup::Found(base) = lookup_dtv::<true>(
                ti.ti_module,
                GLOBAL_GENERATION.load(Ordering::Acquire),
            ) {
                let offset = ti.ti_offset.wrapping_add(NativeArch::TLS_DTV_OFFSET);
                let address = base.as_ptr().wrapping_add(offset);
                if !address.is_null() {
                    return address;
                }
            }
            tls_get_addr_miss(index)
        }

        // Matching the non-unwinding C ABI allows the DTV-hit entry to tail-call
        // this helper without saving registers or installing an unwind landing pad.
        #[cold]
        #[inline(never)]
        extern "C" fn tls_get_addr_miss(index: *const TlsIndex) -> *mut u8 {
            resolve_index(unsafe { &*index })
        }
    } else {
        extern "C" fn tls_get_addr(index: *const TlsIndex) -> *mut u8 {
            resolve_index(unsafe { &*index })
        }
    }
}

fn resolve_index(ti: &TlsIndex) -> *mut u8 {
    let offset = ti.ti_offset.wrapping_add(NativeArch::TLS_DTV_OFFSET);
    if let Some(base) = get_dynamic(ti.ti_module) {
        let address = base.as_ptr().wrapping_add(offset);
        if !address.is_null() {
            return address;
        }
    }
    resolve_index_slow(ti.ti_module, offset)
}

#[cold]
fn resolve_index_slow(mod_id: TlsModuleId, offset: usize) -> *mut u8 {
    match resolve_slow(mod_id, offset) {
        Ok(address) => address.as_ptr(),
        Err(error) => panic!("__tls_get_addr: failed to resolve TLS module {mod_id}: {error}"),
    }
}
