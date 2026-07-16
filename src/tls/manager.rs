use crate::{
    Result, TlsError,
    arch::{
        NativeArch, tlsdesc_resolver_dynamic, tlsdesc_resolver_static, tlsdesc_resolver_undefweak,
    },
    memory::VmAddr,
    relocation::RelocationArch,
    sync::{AtomicUsize, Ordering},
    tls::{
        ModuleTls, TlsDescValue, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsModuleSnapshot,
        TlsRegistry, TlsRequest, TlsResolver, TlsStorage,
    },
};
use alloc::{
    alloc::{alloc, dealloc, handle_alloc_error},
    boxed::Box,
    collections::BTreeMap,
    vec::Vec,
};
use core::{alloc::Layout, ffi::c_void};
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

fn get_module_record(mod_id: TlsModuleId) -> Option<TlsModuleSnapshot> {
    with_registry(|registry| registry.module(mod_id))
}

// -----------------------------------------------------------------------------
// Per-Thread TLS Storage (DTV)
// -----------------------------------------------------------------------------

/// A single entry in the Dynamic Thread Vector (DTV).
/// Points to the actual TLS data block for a specific module.
#[derive(Debug)]
enum DtvEntry {
    Allocated {
        ptr: *mut u8,
        layout: Layout, // We store layout to deallocate properly
    },
    Static {
        ptr: *mut u8,
    },
}

unsafe impl Send for DtvEntry {}
unsafe impl Sync for DtvEntry {}

impl DtvEntry {
    fn ptr(&self) -> *mut u8 {
        match self {
            DtvEntry::Allocated { ptr, .. } => *ptr,
            DtvEntry::Static { ptr } => *ptr,
        }
    }
}

impl Drop for DtvEntry {
    fn drop(&mut self) {
        if let DtvEntry::Allocated { ptr, layout } = self {
            unsafe { dealloc(*ptr, *layout) };
        }
    }
}

/// The Dynamic Thread Vector (DTV) for a single thread.
struct ThreadDtv {
    /// The generation of this DTV. If less than GLOBAL_GENERATION, it may need updates.
    generation: usize,
    /// The vector of TLS blocks, indexed by module ID.
    dtv: Vec<Option<DtvEntry>>,
}

impl ThreadDtv {
    fn new() -> Self {
        let snapshot = with_registry(TlsRegistry::snapshot);
        let mut dtv = Vec::with_capacity(snapshot.slots.len());
        for slot in snapshot.slots {
            let entry = slot.module.and_then(|module| {
                if let TlsStorage::Static(offset) = module.storage {
                    // Safety: We assume that if `tp_offset` is set, the TLS block is
                    // accessible via `tp + offset`.
                    unsafe {
                        let tp = crate::arch::get_thread_pointer();
                        Some(DtvEntry::Static {
                            ptr: tp.offset(offset.get()),
                        })
                    }
                } else {
                    None
                }
            });
            dtv.push(entry);
        }
        Self {
            generation: snapshot.generation,
            dtv,
        }
    }

    /// Synchronize the DTV with the global registry.
    /// Frees memory for modules that have been unloaded or replaced since the last check.
    fn synchronize(&mut self) {
        let Some(snapshot) = with_registry(|registry| registry.snapshot_since(self.generation))
        else {
            return;
        };
        // We only need to check entries that exist in our DTV.
        let check_len = core::cmp::min(self.dtv.len(), snapshot.slots.len());

        for (mod_id, slot_val) in self.dtv.iter_mut().enumerate().take(check_len) {
            let registry_slot = &snapshot.slots[mod_id];

            // If the slot in global registry has a newer generation than what we last saw...
            if registry_slot.generation > self.generation {
                // ...it means the module at this ID was either unloaded or replaced.
                // In either case, our current copy (if any) is stale/zombie.
                // Setting to None will automatically trigger Drop for the old DtvEntry.
                *slot_val = None;
            }
        }

        // Update our local generation to match global
        self.generation = snapshot.generation;
    }

    /// Retrieve the pointer for a specific module, allocating if necessary.
    fn get_or_allocate(&mut self, mod_id: TlsModuleId) -> Option<*mut u8> {
        let index = mod_id.get();

        // Sync with global generation first to cleanup stale modules
        let global_gen = GLOBAL_GENERATION.load(Ordering::Acquire);
        if self.generation < global_gen {
            self.synchronize();
        }

        // Ensure DTV is large enough
        if index >= self.dtv.len() {
            self.dtv.resize_with(index + 1, || None);
        }

        // Check if already allocated
        if let Some(entry) = &self.dtv[index] {
            return Some(entry.ptr());
        }

        // Need to allocate. Look up TLS metadata from global registry.
        let record = get_module_record(mod_id)?;
        if let TlsStorage::Static(offset) = record.storage {
            let tp = unsafe { crate::arch::get_thread_pointer() };
            let ptr = unsafe { tp.offset(offset.get()) };
            self.dtv[index] = Some(DtvEntry::Static { ptr });
            return Some(ptr);
        }
        let source = record.source.as_ref()?;

        // Allocate memory
        let layout = Layout::from_size_align(record.info.memsz, record.info.align).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }

        // Initialize memory (Copy image + Zero BSS)
        let mut init = |image: &[u8]| {
            if image.len() != record.info.filesz {
                return Err(TlsError::ModuleMismatch.into());
            }
            unsafe {
                let slice = core::slice::from_raw_parts_mut(ptr, record.info.memsz);
                let image_len = image.len();
                // Copy initialized data
                slice[..image_len].copy_from_slice(image);
                // Zero initialize remaining part (BSS)
                slice[image_len..].fill(0);
            }
            Ok(())
        };
        if source.with_image(&mut init).is_err() {
            unsafe { dealloc(ptr, layout) };
            return None;
        }

        self.dtv[index] = Some(DtvEntry::Allocated { ptr, layout });

        Some(ptr)
    }

    fn get(&self, mod_id: TlsModuleId) -> Option<*mut u8> {
        let index = mod_id.get();
        let entry = self.dtv.get(index)?.as_ref()?;

        // If our DTV is stale, we check if this specific module has been updated.
        let global_gen = GLOBAL_GENERATION.load(Ordering::Acquire);
        if self.generation < global_gen {
            match with_registry(|registry| registry.slot_generation(mod_id)) {
                Some(generation) if generation <= self.generation => {
                    // This module hasn't been changed since our last sync,
                    // so the pointer in our DTV is still valid.
                }
                _ => return None,
            }
        }

        Some(entry.ptr())
    }
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
        let ptr = crate::os::get_thread_local_ptr();
        if !ptr.is_null() {
            return f(&mut *(ptr as *mut ThreadDtv));
        }
    }

    let tid = crate::os::current_thread_id();
    let mut map = THREAD_DTVS.lock();

    let dtv = map.entry(tid).or_insert_with(|| Box::new(ThreadDtv::new()));
    let dtv_ptr = &mut **dtv as *mut ThreadDtv;

    // Register destructor to cleanup on thread exit and also cache the pointer in TLS.
    // The pointer to the boxed content is stable.
    unsafe {
        crate::os::register_thread_destructor(dtv_destructor, dtv_ptr as *mut _);
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
#[derive(Debug)]
pub struct DefaultTlsResolver;

impl DefaultTlsResolver {
    /// Creates a default TLS resolver handle.
    pub fn new() -> Self {
        Self
    }

    /// Get the current thread pointer.
    /// This uses architecture-specific methods to retrieve the thread pointer.
    pub fn get_thread_pointer() -> *mut u8 {
        unsafe { crate::arch::get_thread_pointer() }
    }

    /// Get the raw pointer to the TLS data for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_ptr(mod_id: TlsModuleId) -> Option<*mut u8> {
        with_current_dtv(|dtv| dtv.get(mod_id))
    }

    /// Get the TLS data as a slice for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_tls_data(mod_id: TlsModuleId) -> Option<&'static [u8]> {
        let memsz = get_module_record(mod_id)?.info.memsz;
        Self::get_ptr(mod_id).map(|ptr| unsafe { core::slice::from_raw_parts(ptr, memsz) })
    }

    /// Get the mutable TLS data as a slice for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_tls_data_mut(mod_id: TlsModuleId) -> Option<&'static mut [u8]> {
        let memsz = get_module_record(mod_id)?.info.memsz;
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

    fn register(info: TlsInfo, request: TlsRequest) -> Result<ModuleTls> {
        let storage = match request {
            TlsRequest::Dynamic => TlsStorage::Dynamic,
            TlsRequest::Static(Some(offset)) => TlsStorage::Static(offset),
            TlsRequest::Static(None) => return Err(TlsError::StaticResolverUnsupported.into()),
        };
        with_registry_mut(|registry| registry.register(info, storage, ModuleData::default()))
    }

    fn init_tls(source: TlsImageSource, mod_id: TlsModuleId) -> Result<()> {
        with_registry_mut(|registry| registry.init(source, mod_id))
    }

    fn unregister(mod_id: TlsModuleId) {
        with_registry_mut(|registry| registry.unregister(mod_id));
    }

    #[inline]
    fn bind_tls_get_addr() -> Result<VmAddr> {
        Ok(VmAddr::from_ptr(tls_get_addr as *const ()))
    }

    #[inline]
    fn resolve_tls_addr(ti: TlsIndex) -> Result<VmAddr> {
        Ok(VmAddr::from_ptr(tls_get_addr(&ti)))
    }

    #[inline]
    fn bind_static_tlsdesc(tpoff: usize) -> Result<TlsDescValue> {
        Ok(TlsDescValue::new(
            VmAddr::from_ptr(tlsdesc_resolver_static as *const ()),
            tpoff,
        ))
    }

    #[inline]
    fn bind_dynamic_tlsdesc(ti: TlsIndex) -> Result<TlsDescValue> {
        let arg = Box::new(TlsDescDynamicArg {
            tls_get_addr: <Self as TlsResolver<NativeArch>>::bind_tls_get_addr()?.get(),
            ti,
        });
        let arg_ptr = VmAddr::from_ptr(arg.as_ref());
        with_registry_mut(|registry| {
            let data = registry
                .data_mut(ti.ti_module)
                .ok_or(TlsError::InvalidModuleId)?;
            data.tls_desc_args.push(arg);
            Ok::<_, crate::Error>(())
        })?;

        Ok(TlsDescValue::new(
            VmAddr::from_ptr(tlsdesc_resolver_dynamic as *const ()),
            arg_ptr.get(),
        ))
    }

    #[inline]
    fn bind_undefweak_tlsdesc(addend: usize) -> Result<TlsDescValue> {
        Ok(TlsDescValue::new(
            VmAddr::from_ptr(tlsdesc_resolver_undefweak as *const ()),
            addend,
        ))
    }
}

// This is exposed to loaded code as a C ABI callback; callers must pass a
// valid `TlsIndex` pointer.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8 {
    let ti = unsafe { &*ti };

    with_current_dtv(|dtv| {
        // Ensure the module's TLS block is allocated for this thread.
        // get_or_allocate now handles synchronization internally.
        match dtv.get_or_allocate(ti.ti_module) {
            Some(base_ptr) => {
                // Return address: Base of block + ABI TLS index offset.
                unsafe { base_ptr.add(ti.ti_offset.wrapping_add(NativeArch::TLS_DTV_OFFSET)) }
            }
            None => {
                // If allocation fails (unknown module ID?), we panic for now.
                // In C world this might be undefined behavior or crash.
                panic!(
                    "__tls_get_addr: Failed to allocate TLS for module {}",
                    ti.ti_module
                );
            }
        }
    })
}

/// Optional: Manually cleanup TLS for the current thread.
/// Should be called when a thread exits to prevent memory leaks in our map.
pub fn cleanup_current_thread_tls() {
    let tid = crate::os::current_thread_id();
    let mut map = THREAD_DTVS.lock();
    map.remove(&tid);
}
