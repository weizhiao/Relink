use crate::{
    Error, Result, TlsError,
    arch::{
        NativeArch, get_thread_pointer, tlsdesc_resolver_dynamic, tlsdesc_resolver_static,
        tlsdesc_resolver_undefweak,
    },
    memory::VmAddr,
    os::{current_thread_id, get_thread_local_ptr, register_thread_destructor},
    relocation::RelocationArch,
    sync::{AtomicUsize, Ordering},
    tls::{
        ModuleTls, ThreadDtv, TlsDescBinding, TlsDescRequest, TlsImageSource, TlsIndex, TlsInfo,
        TlsModuleId, TlsRegistry, TlsRequest, TlsResolver, TlsStorage,
    },
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::ffi::c_void;
use spin::{Mutex, RwLock};

/// Dynamic TLSDESC resolver argument used by the native resolver stub.
#[repr(C)]
#[derive(Debug)]
struct TlsDescDynamicArg {
    tls_get_addr: usize,
    ti: TlsIndex,
}

#[derive(Debug, Default)]
struct ModuleData {
    #[allow(clippy::vec_box)]
    tls_desc_args: Vec<Box<TlsDescDynamicArg>>,
}

/// Global registry for all loaded modules' TLS metadata.
/// This allows any thread to look up how to initialize TLS for a specific module ID.
static MODULE_REGISTRY: RwLock<TlsRegistry<ModuleData>> = RwLock::new(TlsRegistry::new());

#[inline]
fn with_registry<T>(f: impl FnOnce(&TlsRegistry<ModuleData>) -> T) -> T {
    let registry = MODULE_REGISTRY.read();
    f(&registry)
}

#[inline]
fn with_registry_mut<T>(f: impl FnOnce(&mut TlsRegistry<ModuleData>) -> T) -> T {
    let mut registry = MODULE_REGISTRY.write();
    let result = f(&mut registry);
    GLOBAL_GENERATION.store(registry.generation(), Ordering::Release);
    result
}

/// Global generation counter. Incremented whenever a new module is loaded.
/// DTVs use this to detect if they are stale and need updating.
static GLOBAL_GENERATION: AtomicUsize = AtomicUsize::new(0);

fn sync_dtv(dtv: &mut ThreadDtv) -> Result<()> {
    let generation = GLOBAL_GENERATION.load(Ordering::Acquire);
    if dtv.generation() == generation {
        return Ok(());
    }
    let Some(snapshot) = with_registry(|registry| registry.snapshot_since(dtv.generation())) else {
        return Ok(());
    };
    let tp = unsafe { get_thread_pointer() };
    dtv.sync(&snapshot, |offset, _| {
        Ok(unsafe { tp.offset(offset.get()) } as usize)
    })
}

// -----------------------------------------------------------------------------
// Thread Identity and Global Map
// -----------------------------------------------------------------------------

// We simulate TLS by mapping ThreadID -> ThreadDtv.
// This avoids touching thread registers directly.

type ThreadId = usize;

/// The global map of thread DTVs.
/// We use Box<ThreadDtv> to ensure the pointer remains stable even if the map rebalances/grows.
static THREAD_DTVS: Mutex<BTreeMap<ThreadId, Box<ThreadDtv>>> = Mutex::new(BTreeMap::new());

unsafe extern "C" fn dtv_destructor(_ptr: *mut c_void) {
    cleanup_current_thread_tls();
}

/// Get access to the current thread's DTV, creating it if it doesn't exist.
fn with_current_dtv<F, R>(f: F) -> R
where
    F: FnOnce(&mut ThreadDtv) -> R,
{
    // Fast path: try to get the DTV from thread-local storage without locking the global map.
    unsafe {
        let ptr = get_thread_local_ptr();
        if !ptr.is_null() {
            return f(&mut *(ptr as *mut ThreadDtv));
        }
    }

    let tid = current_thread_id();
    let mut map = THREAD_DTVS.lock();

    let dtv = map.entry(tid).or_insert_with(|| Box::new(ThreadDtv::new()));
    let dtv_ptr = &mut **dtv as *mut ThreadDtv;

    // Register destructor to cleanup on thread exit and also cache the pointer in TLS.
    // The pointer to the boxed content is stable.
    unsafe {
        register_thread_destructor(dtv_destructor, dtv_ptr as *mut _);
    }

    f(dtv)
}

// -----------------------------------------------------------------------------
// Public APIs
// -----------------------------------------------------------------------------

/// A same-process TLS resolver implementation.
///
/// This resolver manages TLS modules and per-thread TLS data using the global
/// registry and per-thread DTVs, and exposes native host runtime entry points to
/// loaded code when the target architecture is executable in the current process.
#[derive(Clone, Copy, Debug)]
pub struct DefaultTlsResolver;

impl DefaultTlsResolver {
    /// Creates a default TLS resolver handle.
    pub const fn new() -> Self {
        Self
    }

    /// Get the current thread pointer.
    /// This uses architecture-specific methods to retrieve the thread pointer.
    pub fn get_thread_pointer() -> *mut u8 {
        unsafe { get_thread_pointer() }
    }

    /// Returns the registered TLS segment metadata for a module.
    pub fn get_info(mod_id: TlsModuleId) -> Option<TlsInfo> {
        with_registry(|registry| registry.info(mod_id))
    }

    /// Get the raw pointer to the TLS data for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_ptr(mod_id: TlsModuleId) -> Option<*mut u8> {
        with_current_dtv(|dtv| {
            sync_dtv(dtv).ok()?;
            dtv.resolve(mod_id).ok().map(|address| address as *mut u8)
        })
    }

    /// Get the TLS data as a slice for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_tls_data(mod_id: TlsModuleId) -> Option<&'static [u8]> {
        let memsz = Self::get_info(mod_id)?.memsz;
        Self::get_ptr(mod_id).map(|ptr| unsafe { core::slice::from_raw_parts(ptr, memsz) })
    }

    /// Get the mutable TLS data as a slice for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_tls_data_mut(mod_id: TlsModuleId) -> Option<&'static mut [u8]> {
        let memsz = Self::get_info(mod_id)?.memsz;
        Self::get_ptr(mod_id).map(|ptr| unsafe { core::slice::from_raw_parts_mut(ptr, memsz) })
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

    fn register(&self, info: TlsInfo, request: TlsRequest) -> Result<ModuleTls> {
        let storage = match request {
            TlsRequest::Dynamic => TlsStorage::Dynamic,
            TlsRequest::Static(Some(offset)) => TlsStorage::Static(offset),
            TlsRequest::Static(None) => return Err(TlsError::ResolverUnsupported.into()),
        };
        with_registry_mut(|registry| registry.register(info, storage, ModuleData::default()))
    }

    fn publish(&self, source: TlsImageSource, mod_id: TlsModuleId) -> Result<()> {
        with_registry_mut(|registry| registry.publish(source, mod_id))
    }

    fn unregister(&self, mod_id: TlsModuleId) {
        with_registry_mut(|registry| registry.unregister(mod_id));
    }

    #[inline]
    fn bind_tls_get_addr(&self) -> Result<VmAddr> {
        Ok(VmAddr::from_ptr(tls_get_addr as *const ()))
    }

    #[inline]
    fn bind_tlsdesc(&self, request: TlsDescRequest) -> Result<TlsDescBinding> {
        match request {
            TlsDescRequest::Defined {
                module: ModuleTls::Static { tp_offset, .. },
                offset,
            } => Ok(TlsDescBinding::new(
                VmAddr::from_ptr(tlsdesc_resolver_static as *const ()),
                VmAddr::new(offset)
                    .wrapping_add_signed(tp_offset.get())
                    .get(),
            )),
            TlsDescRequest::Defined {
                module: ModuleTls::Dynamic { mod_id },
                offset,
            } => {
                let ti = TlsIndex {
                    ti_module: mod_id,
                    ti_offset: offset.wrapping_sub(NativeArch::TLS_DTV_OFFSET),
                };
                let arg = Box::new(TlsDescDynamicArg {
                    tls_get_addr: self.bind_tls_get_addr()?.get(),
                    ti,
                });
                let arg_ptr = VmAddr::from_ptr(arg.as_ref());
                with_registry_mut(|registry| {
                    let data = registry
                        .data_mut(mod_id)
                        .ok_or(TlsError::InvalidModuleId { mod_id })?;
                    data.tls_desc_args.push(arg);
                    Ok::<_, Error>(())
                })?;

                Ok(TlsDescBinding::new(
                    VmAddr::from_ptr(tlsdesc_resolver_dynamic as *const ()),
                    arg_ptr.get(),
                ))
            }
            TlsDescRequest::UndefinedWeak { addend } => Ok(TlsDescBinding::new(
                VmAddr::from_ptr(tlsdesc_resolver_undefweak as *const ()),
                addend,
            )),
        }
    }
}

// This is exposed to loaded code as a C ABI callback; callers must pass a
// valid `TlsIndex` pointer.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8 {
    let ti = unsafe { &*ti };

    with_current_dtv(|dtv| {
        match sync_dtv(dtv).and_then(|()| dtv.resolve(ti.ti_module)) {
            Ok(base) => {
                // Return address: Base of block + ABI TLS index offset.
                unsafe {
                    (base as *mut u8).add(ti.ti_offset.wrapping_add(NativeArch::TLS_DTV_OFFSET))
                }
            }
            Err(error) => {
                panic!(
                    "__tls_get_addr: failed to resolve TLS module {}: {error}",
                    ti.ti_module,
                );
            }
        }
    })
}

/// Optional: Manually cleanup TLS for the current thread.
/// Should be called when a thread exits to prevent memory leaks in our map.
pub fn cleanup_current_thread_tls() {
    let tid = current_thread_id();
    let mut map = THREAD_DTVS.lock();
    map.remove(&tid);
}
