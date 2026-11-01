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
    // Some(generation) is readable; None excludes access during an update.
    // Some(0) represents the initial empty DTV, not an update in progress.
    published_generation: Cell<Option<usize>>,
    dtv: UnsafeCell<ThreadDtv>,
}

#[cfg(feature = "std")]
impl LocalDtv {
    const fn new() -> Self {
        Self {
            published_generation: Cell::new(Some(0)),
            dtv: UnsafeCell::new(ThreadDtv::new()),
        }
    }

    #[inline]
    fn lookup(&self, mod_id: TlsModuleId, generation: usize) -> DtvLookup {
        if generation == 0 {
            return DtvLookup::Missing;
        }
        if self.published_generation.get() != Some(generation) {
            return DtvLookup::Stale;
        }
        // SAFETY: A matching nonzero generation is published only when there is
        // no mutable DTV reference. Updates unpublish before borrowing, including
        // while allocation/free can reenter. This leaf query cannot allocate,
        // call user code or drop values; only a copied block pointer escapes.
        let dtv = unsafe { &*self.dtv.get() };
        dtv.get(mod_id).map_or(DtvLookup::Missing, DtvLookup::Found)
    }

    fn with_mut<R>(&self, f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
        assert!(
            self.published_generation.replace(None).is_some(),
            "reentrant managed TLS storage update"
        );
        let _update = DtvUpdate(self);
        // SAFETY: None excludes both nested mutations and reentrant lookups
        // that could create shared references into the DTV. The closure
        // cannot return a reference borrowing this argument. The guard publishes
        // again after that reference ends, including when the closure unwinds.
        f(unsafe { &mut *self.dtv.get() })
    }
}

#[cfg(feature = "std")]
struct DtvUpdate<'a>(&'a LocalDtv);

#[cfg(feature = "std")]
impl Drop for DtvUpdate<'_> {
    fn drop(&mut self) {
        // SAFETY: The closure and all references it borrowed have ended. Neither
        // reading the generation nor publishing it can reenter.
        let generation = unsafe { &*self.0.dtv.get() }.generation();
        self.0.published_generation.set(Some(generation));
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))] {
        mod pthread {
            //! Heap-owned DTV storage, reclaimed on the second pthread destructor round.
            //!
            //! std TLS only caches a borrowed pointer; reclaiming that cache cannot free the
            //! DTV. Delaying one round covers first-round runtime cleanup, but does not promise
            //! to outlive arbitrary, repeatedly rearmed foreign destructors. Access after
            //! second-round reclamation is unsupported.

            use super::{DtvLookup, LocalDtv, Result, ThreadDtv, TlsError, TlsModuleId};
            use alloc::boxed::Box;
            use core::{cell::Cell, ffi::c_void, ptr::NonNull};

            // Only the pthread slot carries this tag; the std cache holds an untagged
            // pointer so ordinary lookups do not need to mask it.
            const RETIRING: usize = 1;
            const _: () = assert!(core::mem::align_of::<LocalDtv>() > RETIRING);

            // Never dereferenced. Blocks reentry while the DTV allocation is being freed.
            const DESTROYED: *mut LocalDtv = core::ptr::without_provenance_mut(RETIRING);

            std::thread_local! {
                static DTV_CACHE: Cell<*mut LocalDtv> = const { Cell::new(core::ptr::null_mut()) };
            }

            #[inline]
            fn cache_dtv(ptr: *mut LocalDtv) {
                let _ = DTV_CACHE.try_with(|cache| cache.set(ptr));
            }

            // The key lives for the runtime's lifetime. Failed creation can be retried.
            static KEY: spin::Once<libc::pthread_key_t> = spin::Once::new();

            #[inline]
            fn current_dtv<const CACHED_ONLY: bool>() -> *mut LocalDtv {
                let ptr = DTV_CACHE.try_with(Cell::get).unwrap_or(core::ptr::null_mut());
                if CACHED_ONLY || !ptr.is_null() {
                    return ptr;
                }
                // The pthread slot is authoritative even when std has reclaimed the cache.
                let Some(&key) = KEY.get() else {
                    return core::ptr::null_mut();
                };
                let ptr = unsafe { libc::pthread_getspecific(key) }.cast::<LocalDtv>();
                // Preserve the terminal sentinel; only a live pointer's tag is stripped.
                let ptr = if ptr == DESTROYED {
                    ptr
                } else {
                    ptr.map_addr(|addr| addr & !RETIRING)
                };
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

            fn rearm(value: *mut LocalDtv) {
                // pthread clears the slot before calling destroy. Restore either its live
                // tagged pointer or its terminal marker before any allocator can reenter us.
                let code = unsafe { libc::pthread_setspecific(*KEY.get().unwrap(), value.cast()) };
                if code != 0 {
                    // Losing this state could resurrect a DTV during teardown. No caller can
                    // receive an error from a pthread destructor, so fail closed.
                    std::process::abort();
                }
            }

            unsafe extern "C" fn destroy(value: *mut c_void) {
                let ptr = value.cast::<LocalDtv>();
                if ptr == DESTROYED {
                    return;
                }
                if ptr.addr() & RETIRING == 0 {
                    rearm(ptr.map_addr(|addr| addr | RETIRING));
                    return;
                }
                // SAFETY: stripping the tag restores the pointer from Box::into_raw,
                // preserving its provenance. The second callback consumes it exactly once.
                let ptr = ptr.map_addr(|addr| addr & !RETIRING);
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
                unsafe { &*ptr }.lookup(mod_id, generation)
            }

            #[inline]
            pub(in crate::tls) fn with_dtv<R>(f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
                let ptr = current_dtv::<false>();
                assert_ne!(ptr, DESTROYED, "managed TLS thread storage has been destroyed");
                let dtv = match NonNull::new(ptr) {
                    Some(dtv) => dtv,
                    None => create_dtv(),
                };
                unsafe { dtv.as_ref() }.with_mut(f)
            }

            #[cold]
            #[inline(never)]
            fn create_dtv() -> NonNull<LocalDtv> {
                // Managed TLS registration creates the key before publishing a module ID.
                let key = *KEY
                    .get()
                    .expect("managed TLS must be registered before resolving it");
                // Recursive creation from an allocator callback is unsupported. Until
                // installation succeeds, non-allocating queries still see an empty slot.
                let mut owned = Box::new(LocalDtv::new());
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
        pub(super) fn with_dtv<R>(f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
            DTV.with(|dtv| dtv.with_mut(f))
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

        pub(super) fn with_dtv<R>(_f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
            panic!("managed TLS thread storage requires std")
        }
    }
}
