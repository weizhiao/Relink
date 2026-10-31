//! Dynamic TLS blocks and thread-owned storage for the default resolver.

use super::{TlsInfo, TlsModuleId, TlsRegistry};
use crate::{Result, TlsError};
use alloc::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error},
    vec::Vec,
};
#[cfg(feature = "std")]
use core::cell::{Cell, UnsafeCell};
use core::{alloc::Layout, ptr::NonNull};

// Owns only the allocation; template and module lifetimes stay with the caller.
struct TlsBlock {
    ptr: NonNull<u8>,
    layout: Layout,
}

unsafe impl Send for TlsBlock {}

impl TlsBlock {
    fn new(info: TlsInfo, image: &[u8]) -> Result<Self> {
        info.validate()?;
        if image.len() != info.filesz {
            return Err(TlsError::ModuleMismatch.into());
        }
        let layout = Layout::from_size_align(info.memsz.max(1), info.align.max(1))
            .map_err(|_| TlsError::InvalidInfo)?;
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })
            .unwrap_or_else(|| handle_alloc_error(layout));
        unsafe { core::ptr::copy_nonoverlapping(image.as_ptr(), ptr.as_ptr(), image.len()) };
        Ok(Self { ptr, layout })
    }
}

impl Drop for TlsBlock {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Per-thread cache of dynamically allocated TLS blocks.
///
/// Static and external storage remain with their providers. This type does not
/// define an architecture's ABI-visible DTV layout and retains no module owners.
/// IDs must use [`super::TlsRegistry`]'s slot/incarnation encoding. Resolvers
/// with another ID format must provide their own thread storage.
pub struct ThreadDtv {
    generation: usize,
    blocks: Vec<Option<(TlsModuleId, TlsBlock)>>,
}

impl ThreadDtv {
    /// Creates an empty per-thread DTV.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            blocks: Vec::new(),
        }
    }

    /// Returns the registry generation represented by this DTV.
    #[inline]
    pub const fn generation(&self) -> usize {
        self.generation
    }

    /// Discards blocks whose full IDs are absent from the associated registry.
    /// Hold the registry's read lock through this call when it is shared.
    /// This only frees TLS allocations; it does not retain owners or invoke providers.
    pub fn sync(&mut self, registry: &TlsRegistry) {
        if self.generation == registry.generation() {
            return;
        }
        for slot in &mut self.blocks {
            if let Some((id, _)) = slot
                && !registry.contains(*id)
            {
                *slot = None;
            }
        }
        self.generation = registry.generation();
    }

    /// Returns a cached block, initializing it from template bytes on first use.
    ///
    /// `mod_id` must identify a live registration in the associated registry.
    /// Reusing a slot with a new incarnation replaces its old block. The caller
    /// keeps the template alive until this borrow ends; this operation invokes
    /// no image-provider callbacks and releases no module owners.
    pub fn get_or_init(
        &mut self,
        mod_id: TlsModuleId,
        info: TlsInfo,
        image: &[u8],
    ) -> Result<NonNull<u8>> {
        if let Some(ptr) = self.get(mod_id) {
            return Ok(ptr);
        }
        let index = mod_id.slot().ok_or(TlsError::InvalidModuleId { mod_id })?;
        let block = TlsBlock::new(info, image)?;
        if self.blocks.len() <= index {
            self.blocks.resize_with(index + 1, || None);
        }
        let ptr = block.ptr;
        self.blocks[index] = Some((mod_id, block));
        Ok(ptr)
    }

    /// Returns an already allocated dynamic block.
    #[inline]
    pub fn get(&self, mod_id: TlsModuleId) -> Option<NonNull<u8>> {
        let (id, block) = self.blocks.get(mod_id.slot()?)?.as_ref()?;
        (*id == mod_id).then_some(block.ptr)
    }
}

impl Default for ThreadDtv {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(super) enum DtvLookup {
    Missing,
    Stale,
    Found(NonNull<u8>),
}

#[cfg(feature = "std")]
struct LocalDtv {
    // Zero is unpublished. Registry generations never wrap, and a registered
    // module always has a nonzero generation.
    published_generation: Cell<usize>,
    updating: Cell<bool>,
    dtv: UnsafeCell<ThreadDtv>,
}

#[cfg(feature = "std")]
impl LocalDtv {
    const fn new() -> Self {
        Self {
            published_generation: Cell::new(0),
            updating: Cell::new(false),
            dtv: UnsafeCell::new(ThreadDtv::new()),
        }
    }

    #[inline]
    fn lookup(&self, mod_id: TlsModuleId, generation: usize) -> DtvLookup {
        if generation == 0 {
            return DtvLookup::Missing;
        }
        if self.published_generation.get() != generation {
            return DtvLookup::Stale;
        }
        // SAFETY: A matching nonzero generation is published only when there is
        // no mutable DTV reference. Updates unpublish before borrowing, including
        // while allocation/free can reenter. This leaf query cannot allocate,
        // call user code or drop values; only a copied block pointer escapes.
        let dtv = unsafe { &*self.dtv.get() };
        dtv.get(mod_id).map_or(DtvLookup::Missing, DtvLookup::Found)
    }

    fn with_mut<R>(&self, f: impl FnOnce(&mut ThreadDtv) -> R) -> Result<R> {
        if self.updating.replace(true) {
            return Err(TlsError::ThreadStorageUnavailable.into());
        }
        self.published_generation.set(0);
        let _update = DtvUpdate(self);
        // SAFETY: The update flag excludes nested mutations, and generation zero
        // prevents reentrant lookups from creating shared references. The closure
        // cannot return a reference borrowing this argument. The guard publishes
        // again after that reference ends, including when the closure unwinds.
        Ok(f(unsafe { &mut *self.dtv.get() }))
    }
}

#[cfg(feature = "std")]
struct DtvUpdate<'a>(&'a LocalDtv);

#[cfg(feature = "std")]
impl Drop for DtvUpdate<'_> {
    fn drop(&mut self) {
        // SAFETY: The closure and all references it borrowed have ended. Neither
        // reading the generation nor publishing the two cells can reenter.
        let generation = unsafe { &*self.0.dtv.get() }.generation();
        self.0.published_generation.set(generation);
        self.0.updating.set(false);
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))] {
        mod pthread {
            //! Heap-owned DTV storage, reclaimed on the second pthread destructor round.
            //!
            //! std TLS only caches a borrowed pointer; reclaiming that cache cannot free the
            //! DTV. Delaying one round covers first-round runtime cleanup, but does not promise
            //! to outlive arbitrary, repeatedly rearmed foreign destructors.

            use super::{DtvLookup, LocalDtv, Result, ThreadDtv, TlsError, TlsModuleId};
            use alloc::boxed::Box;
            use core::{cell::Cell, ffi::c_void, ptr::NonNull};

            struct Storage {
                retiring: Cell<bool>,
                dtv: LocalDtv,
            }

            // Never dereferenced. Retain this marker through the remaining destructor rounds
            // so an unavailable or recreated std cache cannot resurrect the DTV.
            const DESTROYED: *mut Storage = core::ptr::without_provenance_mut(1);

            std::thread_local! {
                static DTV_CACHE: Cell<*mut Storage> = const { Cell::new(core::ptr::null_mut()) };
            }

            #[inline]
            fn cache_dtv(ptr: *mut Storage) {
                let _ = DTV_CACHE.try_with(|cache| cache.set(ptr));
            }

            // The key lives for the runtime's lifetime. Failed creation can be retried.
            static KEY: spin::Once<libc::pthread_key_t> = spin::Once::new();

            #[inline]
            fn current_dtv<const CACHED_ONLY: bool>() -> *mut Storage {
                let ptr = DTV_CACHE.try_with(Cell::get).unwrap_or(core::ptr::null_mut());
                if CACHED_ONLY || !ptr.is_null() {
                    return ptr;
                }
                // The pthread slot is authoritative even when std has reclaimed the cache.
                let Some(&key) = KEY.get() else {
                    return core::ptr::null_mut();
                };
                let ptr = unsafe { libc::pthread_getspecific(key) }.cast::<Storage>();
                if !ptr.is_null() {
                    cache_dtv(ptr);
                }
                ptr
            }

            pub(in crate::tls) fn ensure_supported() -> Result<()> {
                KEY.try_call_once(|| {
                    let mut key = 0;
                    let code = unsafe { libc::pthread_key_create(&mut key, Some(destroy)) };
                    if code != 0 {
                        return Err(TlsError::ThreadStorageFailed { code }.into());
                    }
                    Ok(key)
                })
                .map(|_| ())
            }

            fn rearm(value: *mut Storage) {
                // pthread clears the slot before calling destroy. Restore either its live
                // pointer or its terminal marker before any allocator can reenter us.
                let code = unsafe { libc::pthread_setspecific(*KEY.get().unwrap(), value.cast()) };
                if code != 0 {
                    // Losing this state could resurrect a DTV during teardown. No caller can
                    // receive an error from a pthread destructor, so fail closed.
                    std::process::abort();
                }
            }

            unsafe extern "C" fn destroy(value: *mut c_void) {
                let ptr = value.cast::<Storage>();
                if ptr == DESTROYED {
                    rearm(DESTROYED);
                    return;
                }
                // SAFETY: this pointer came from Box::into_raw on this thread. It remains
                // owned by the slot until the second callback consumes it exactly once.
                let storage = unsafe { &*ptr };
                if !storage.retiring.replace(true) {
                    rearm(ptr);
                    return;
                }
                rearm(DESTROYED);
                cache_dtv(DESTROYED);
                // Both access paths now reject reentry, including attempts to create a DTV.
                unsafe { drop(Box::from_raw(ptr)) };
            }

            #[inline]
            pub(in crate::tls) fn lookup_dtv<const CACHED_ONLY: bool>(
                mod_id: TlsModuleId,
                generation: usize,
            ) -> DtvLookup {
                // The ELF ABI entry queries only the cached pointer to remain a leaf on
                // native-TLS targets. Ordinary resolution can fall back to the pthread slot.
                let ptr = current_dtv::<CACHED_ONLY>();
                // Null and the destroyed sentinel must never be dereferenced.
                if ptr.addr() <= DESTROYED.addr() {
                    return DtvLookup::Missing;
                }
                // Only this thread accesses its slot; LocalDtv exposes only a published generation.
                unsafe { &*ptr }.dtv.lookup(mod_id, generation)
            }

            #[inline]
            pub(in crate::tls) fn with_dtv<R>(f: impl FnOnce(&mut ThreadDtv) -> R) -> Result<R> {
                let ptr = current_dtv::<false>();
                if ptr == DESTROYED {
                    return Err(TlsError::ThreadStorageUnavailable.into());
                }
                let dtv = match NonNull::new(ptr) {
                    Some(dtv) => dtv,
                    None => create_dtv(),
                };
                unsafe { dtv.as_ref() }.dtv.with_mut(f)
            }

            #[cold]
            #[inline(never)]
            fn create_dtv() -> NonNull<Storage> {
                // Managed TLS registration creates the key before publishing a module ID.
                let key = *KEY
                    .get()
                    .expect("managed TLS must be registered before resolving it");
                // Recursive creation from an allocator callback is unsupported. Until
                // installation succeeds, non-allocating queries still see an empty slot.
                let mut owned = Box::new(Storage {
                    retiring: Cell::new(false),
                    dtv: LocalDtv::new(),
                });
                let ptr = NonNull::from(&mut *owned);
                let code = unsafe { libc::pthread_setspecific(key, ptr.as_ptr().cast()) };
                assert_eq!(code, 0, "failed to install managed TLS thread storage");
                // Transfer ownership only after successful installation.
                let _ = Box::into_raw(owned);
                cache_dtv(ptr.as_ptr());
                ptr
            }
        }

        pub(super) use pthread::{ensure_supported, lookup_dtv, with_dtv};
    } else if #[cfg(feature = "std")] {
        std::thread_local! {
            static DTV: LocalDtv = const { LocalDtv::new() };
        }

        pub(super) fn ensure_supported() -> Result<()> {
            Ok(())
        }

        #[inline]
        pub(super) fn lookup_dtv<const CACHED_ONLY: bool>(
            mod_id: TlsModuleId,
            generation: usize,
        ) -> DtvLookup {
            DTV.try_with(|dtv| dtv.lookup(mod_id, generation))
                .unwrap_or(DtvLookup::Missing)
        }

        #[inline]
        pub(super) fn with_dtv<R>(f: impl FnOnce(&mut ThreadDtv) -> R) -> Result<R> {
            DTV.try_with(|dtv| dtv.with_mut(f))
                .map_err(|_| TlsError::ThreadStorageUnavailable)?
        }
    } else {
        pub(super) fn ensure_supported() -> Result<()> {
            Err(TlsError::ResolverUnsupported.into())
        }

        pub(super) fn lookup_dtv<const CACHED_ONLY: bool>(
            _mod_id: TlsModuleId,
            _generation: usize,
        ) -> DtvLookup {
            DtvLookup::Missing
        }

        pub(super) fn with_dtv<R>(_f: impl FnOnce(&mut ThreadDtv) -> R) -> Result<R> {
            Err(TlsError::ResolverUnsupported.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{TlsOwner, manager::ManagedTls};

    fn info() -> TlsInfo {
        TlsInfo {
            vaddr: 0,
            filesz: 4,
            memsz: 16,
            align: 8,
        }
    }

    #[test]
    fn sync_discards_unregistered_blocks() {
        let mut registry = TlsRegistry::new();
        let owner = TlsOwner::new(ManagedTls::new());
        let mod_id = unsafe { registry.register(info(), None, &owner) }
            .unwrap()
            .mod_id();
        let mut dtv = ThreadDtv::new();
        let address = dtv.get_or_init(mod_id, info(), &[1, 2, 3, 4]).unwrap();
        dtv.sync(&registry);
        assert_eq!(dtv.get(mod_id), Some(address));

        drop(registry.unregister(mod_id));
        let replacement = unsafe { registry.register(info(), None, &owner) }
            .unwrap()
            .mod_id();
        assert_eq!(mod_id.slot(), replacement.slot());
        dtv.sync(&registry);
        assert_eq!(dtv.get(mod_id), None);
        assert_eq!(dtv.get(replacement), None);
        assert_eq!(dtv.generation(), registry.generation());
    }

    #[test]
    fn dynamic_blocks_are_allocated_lazily() {
        let mut registry = TlsRegistry::new();
        let owner = TlsOwner::new(ManagedTls::new());
        let mod_id = unsafe { registry.register(info(), None, &owner) }
            .unwrap()
            .mod_id();
        let mut dtv = ThreadDtv::new();
        dtv.sync(&registry);
        assert_eq!(dtv.get(mod_id), None);
        let address = dtv.get_or_init(mod_id, info(), &[1, 2, 3, 4]).unwrap();
        assert_eq!(dtv.get(mod_id), Some(address));
        // A cache hit must not initialize or validate a replacement template.
        assert_eq!(dtv.get_or_init(mod_id, info(), &[]).unwrap(), address);
    }

    #[test]
    fn blocks_copy_the_template_and_zero_the_remainder() {
        let block = TlsBlock::new(info(), &[1, 2, 3, 4]).unwrap();
        let bytes = unsafe { core::slice::from_raw_parts(block.ptr.as_ptr(), info().memsz) };
        assert_eq!(&bytes[..4], &[1, 2, 3, 4]);
        assert_eq!(&bytes[4..], &[0; 12]);
    }
}
