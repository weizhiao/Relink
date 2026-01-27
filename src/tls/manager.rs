use crate::{
    Result,
    sync::{AtomicUsize, Ordering},
    tls::{TlsIndex, TlsInfo, TlsResolver},
    tls_error,
};
use alloc::{
    alloc::{alloc, dealloc, handle_alloc_error},
    boxed::Box,
    collections::BTreeMap,
    vec::Vec,
};
use core::{
    alloc::Layout,
    ffi::c_void,
};
use spin::{Mutex, RwLock};

#[derive(Debug)]
struct ModuleSlot {
    /// The generation number when this slot was last updated (loaded or unloaded).
    generation: usize,
    /// The TLS template. If None, the module at this ID has been unloaded.
    template: Option<ModuleTlsTemplate>,
}

/// Stores the static TLS template information for a loaded ELF module.
#[derive(Debug, Clone)]
struct ModuleTlsTemplate {
    image: &'static [u8],
    memsz: usize,
    align: usize,
    tp_offset: Option<isize>,
}

/// Global registry for all loaded modules' TLS metadata.
/// This allows any thread to look up how to initialize TLS for a specific module ID.
static MODULE_REGISTRY: RwLock<Vec<ModuleSlot>> = RwLock::new(Vec::new());

/// Atomic counter for generating unique module IDs.
static NEXT_MODULE_ID: AtomicUsize = AtomicUsize::new(1);

/// Global generation counter. Incremented whenever a new module is loaded.
/// DTVs use this to detect if they are stale and need updating.
static GLOBAL_GENERATION: AtomicUsize = AtomicUsize::new(0);

fn register_module(tls_info: &TlsInfo, tp_offset: Option<isize>) -> usize {
    let mut registry = MODULE_REGISTRY.write();

    // Try to find a free slot (excluding index 0 as it's typically unused/reserved)
    let mod_id = registry
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, slot)| slot.template.is_none())
        .map(|(id, _)| id)
        .unwrap_or_else(|| NEXT_MODULE_ID.fetch_add(1, Ordering::SeqCst));

    if mod_id >= registry.len() {
        registry.resize_with(mod_id + 1, || ModuleSlot {
            generation: 0,
            template: None,
        });
    }

    let template = ModuleTlsTemplate {
        image: tls_info.image,
        memsz: tls_info.memsz,
        align: tls_info.align,
        tp_offset,
    };

    // Increment global generation
    let new_gen = GLOBAL_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

    registry[mod_id] = ModuleSlot {
        generation: new_gen,
        template: Some(template),
    };

    #[cfg(feature = "log")]
    log::debug!(
        "Registered TLS module: ID {}, memsz {}, align {}, tp_offset {:?}",
        mod_id,
        tls_info.memsz,
        tls_info.align,
        tp_offset
    );

    mod_id
}

/// Mark a module as unloaded in the registry.
/// This triggers lazy reclamation in threads that previously used this module.
fn unregister_module(mod_id: usize) {
    let mut registry = MODULE_REGISTRY.write();
    assert!(mod_id < registry.len(), "Invalid module ID");
    // Increment global generation
    let new_gen = GLOBAL_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

    // Mark as unloaded (None) and update generation
    registry[mod_id] = ModuleSlot {
        generation: new_gen,
        template: None, // This signals threads to free their local copy
    };

    #[cfg(feature = "log")]
    log::debug!("Unregistered TLS module: ID {}", mod_id);
}

fn get_module_template(mod_id: usize) -> Option<ModuleTlsTemplate> {
    let registry = MODULE_REGISTRY.read();
    registry.get(mod_id).and_then(|slot| slot.template.clone())
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
        let registry = MODULE_REGISTRY.read();
        let mut dtv = Vec::with_capacity(registry.len());
        for slot in registry.iter() {
            let entry = slot.template.as_ref().and_then(|t| {
                if let Some(offset) = t.tp_offset {
                    // Safety: We assume that if `tp_offset` is set, the TLS block is
                    // accessible via `tp + offset`.
                    unsafe {
                        let tp = crate::arch::get_thread_pointer();
                        Some(DtvEntry::Static {
                            ptr: tp.offset(offset),
                        })
                    }
                } else {
                    None
                }
            });
            dtv.push(entry);
        }
        Self {
            generation: GLOBAL_GENERATION.load(Ordering::Acquire),
            dtv,
        }
    }

    /// Synchronize the DTV with the global registry.
    /// Frees memory for modules that have been unloaded or replaced since the last check.
    fn synchronize(&mut self, global_gen: usize) {
        let registry = MODULE_REGISTRY.read();

        // We only need to check entries that exist in our DTV.
        let check_len = core::cmp::min(self.dtv.len(), registry.len());

        for (mod_id, slot_val) in self.dtv.iter_mut().enumerate().take(check_len) {
            let registry_slot = &registry[mod_id];

            // If the slot in global registry has a newer generation than what we last saw...
            if registry_slot.generation > self.generation {
                // ...it means the module at this ID was either unloaded or replaced.
                // In either case, our current copy (if any) is stale/zombie.
                // Setting to None will automatically trigger Drop for the old DtvEntry.
                *slot_val = None;
            }
        }

        // Update our local generation to match global
        self.generation = global_gen;
    }

    /// Retrieve the pointer for a specific module, allocating if necessary.
    fn get_or_allocate(&mut self, mod_id: usize) -> Option<*mut u8> {
        // Sync with global generation first to cleanup stale modules
        let global_gen = GLOBAL_GENERATION.load(Ordering::Acquire);
        if self.generation < global_gen {
            self.synchronize(global_gen);
        }

        // Ensure DTV is large enough
        if mod_id >= self.dtv.len() {
            self.dtv.resize_with(mod_id + 1, || None);
        }

        // Check if already allocated
        if let Some(entry) = &self.dtv[mod_id] {
            return Some(entry.ptr());
        }

        // Need to allocate. Look up template from global registry.
        let template = get_module_template(mod_id)?;

        // Allocate memory
        let layout = Layout::from_size_align(template.memsz, template.align).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }

        // Initialize memory (Copy image + Zero BSS)
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr, template.memsz);
            let image_len = template.image.len();
            // Copy initialized data
            slice[..image_len].copy_from_slice(template.image);
            // Zero initialize remaining part (BSS)
            slice[image_len..].fill(0);
        }

        self.dtv[mod_id] = Some(DtvEntry::Allocated { ptr, layout });

        Some(ptr)
    }

    fn get(&self, mod_id: usize) -> Option<*mut u8> {
        let entry = self.dtv.get(mod_id)?.as_ref()?;

        // If our DTV is stale, we check if this specific module has been updated.
        let global_gen = GLOBAL_GENERATION.load(Ordering::Acquire);
        if self.generation < global_gen {
            let registry = MODULE_REGISTRY.read();
            match registry.get(mod_id) {
                Some(slot) if slot.generation <= self.generation => {
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

#[derive(Debug)]
pub struct DefaultTlsResolver;

impl DefaultTlsResolver {
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
    pub fn get_ptr(mod_id: usize) -> Option<*mut u8> {
        with_current_dtv(|dtv| dtv.get(mod_id))
    }

    /// Get the TLS data as a slice for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_tls_data(mod_id: usize) -> Option<&'static [u8]> {
        let memsz = get_module_template(mod_id)?.memsz;
        Self::get_ptr(mod_id).map(|ptr| unsafe { core::slice::from_raw_parts(ptr, memsz) })
    }

    /// Get the mutable TLS data as a slice for the current thread and a specific module.
    ///
    /// This will automatically synchronize the thread's TLS state and allocate the
    /// TLS block if it hasn't been initialized yet.
    pub fn get_tls_data_mut(mod_id: usize) -> Option<&'static mut [u8]> {
        let memsz = get_module_template(mod_id)?.memsz;
        Self::get_ptr(mod_id).map(|ptr| unsafe { core::slice::from_raw_parts_mut(ptr, memsz) })
    }
}

impl TlsResolver for DefaultTlsResolver {
    fn register(tls_info: &TlsInfo) -> Result<usize> {
        let id = register_module(tls_info, None);
        Ok(id)
    }

    fn register_static(_tls_info: &TlsInfo) -> Result<(usize, isize)> {
        Err(tls_error("unsupport static tls"))
    }

    fn add_static_tls(tls_info: &TlsInfo, offset: isize) -> Result<usize> {
        let id = register_module(tls_info, Some(offset));
        Ok(id)
    }

    fn unregister(mod_id: usize) {
        unregister_module(mod_id);
    }

    extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8 {
        let ti = unsafe { &*ti };

        with_current_dtv(|dtv| {
            // Ensure the module's TLS block is allocated for this thread.
            // get_or_allocate now handles synchronization internally.
            match dtv.get_or_allocate(ti.ti_module) {
                Some(base_ptr) => {
                    // Return address: Base of block + Offset
                    unsafe { base_ptr.add(ti.ti_offset) }
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
}

/// Optional: Manually cleanup TLS for the current thread.
/// Should be called when a thread exits to prevent memory leaks in our map.
pub fn cleanup_current_thread_tls() {
    let tid = crate::os::current_thread_id();
    let mut map = THREAD_DTVS.lock();
    map.remove(&tid);
}
