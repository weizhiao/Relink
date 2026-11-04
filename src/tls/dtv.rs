//! Dynamic TLS blocks and thread-owned storage for the default resolver.

use super::{TlsInfo, TlsModuleId, TlsRegistry};
use crate::{Result, TlsError};
use alloc::alloc::{alloc, dealloc, handle_alloc_error, realloc};
use core::{alloc::Layout, ptr::NonNull};

// The address is the first word; allocation metadata is only needed on teardown.
#[repr(C)]
struct TlsBlock {
    ptr: NonNull<u8>,
    layout: Layout,
}

unsafe impl Send for TlsBlock {}

impl TlsBlock {
    // Real blocks allocate at least one byte, so a zero-sized layout owns nothing.
    const EMPTY: Self = Self {
        ptr: NonNull::dangling(),
        layout: Layout::new::<()>(),
    };

    fn new(info: TlsInfo, image: &[u8]) -> Result<Self> {
        info.validate()?;
        if image.len() != info.filesz {
            return Err(TlsError::ModuleMismatch.into());
        }
        let layout = Layout::from_size_align(info.memsz.max(1), info.align.max(1))
            .map_err(|_| TlsError::InvalidInfo)?;
        let ptr =
            NonNull::new(unsafe { alloc(layout) }).unwrap_or_else(|| handle_alloc_error(layout));
        // Initialized bytes come from the template; only BSS needs zeroing.
        unsafe {
            core::ptr::copy_nonoverlapping(image.as_ptr(), ptr.as_ptr(), image.len());
            ptr.as_ptr()
                .add(image.len())
                .write_bytes(0, info.memsz - image.len());
        }
        Ok(Self { ptr, layout })
    }
}

impl Drop for TlsBlock {
    fn drop(&mut self) {
        if self.layout.size() != 0 {
            unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
        }
    }
}

#[repr(C)]
struct DtvSlot {
    id: TlsModuleId,
    block: TlsBlock,
}

impl DtvSlot {
    const EMPTY: Self = Self {
        id: TlsModuleId::RESERVED,
        block: TlsBlock::EMPTY,
    };
}

// One allocation holds the validity header followed by initialized slots. A
// published pointer is enough to check the generation and index the slots;
// no intermediate owner or Vec backing-pointer load is needed.
#[repr(C)]
struct DtvHeader {
    generation: usize,
    len: usize,
    slots: [DtvSlot; 0],
}

const EMPTY_DTV: DtvHeader = DtvHeader {
    generation: 0,
    len: 0,
    slots: [],
};
const SLOTS_OFFSET: usize = core::mem::offset_of!(DtvHeader, slots);

impl DtvHeader {
    #[inline]
    // The pointer must retain provenance for the whole allocation, not be
    // derived from a reference narrowed to the header. The table must be live
    // and immutable for the duration of this leaf lookup.
    unsafe fn get(table: *const Self, mod_id: TlsModuleId) -> Option<NonNull<u8>> {
        // A zero slot wraps to usize::MAX and is rejected by the bounds check.
        let index = (mod_id.get() & TlsModuleId::SLOT_MASK).wrapping_sub(1);
        if index >= unsafe { (*table).len } {
            return None;
        }
        // SAFETY: Every header with nonzero len is followed by that many initialized
        // slots in the same allocation. EMPTY_DTV has no slots and cannot get here.
        let slot = unsafe {
            &*table
                .cast::<u8>()
                .add(SLOTS_OFFSET)
                .cast::<DtvSlot>()
                .add(index)
        };
        (slot.id == mod_id).then_some(slot.block.ptr)
    }

    #[inline]
    unsafe fn lookup(table: *const Self, mod_id: TlsModuleId, generation: usize) -> DtvLookup {
        if unsafe { (*table).generation } != generation {
            return DtvLookup::Stale;
        }
        unsafe { Self::get(table, mod_id) }.map_or(DtvLookup::Missing, DtvLookup::Found)
    }
}

/// Owns a per-thread cache of dynamically allocated TLS blocks.
///
/// One allocation contains the DTV header followed by its initialized slots.
/// Static and external storage remain with their providers. This type does not
/// define an architecture's ABI-visible DTV layout and retains no module owners.
/// IDs must use [`super::TlsRegistry`]'s slot/incarnation encoding. Resolvers
/// with another ID format must provide their own thread storage.
pub struct ThreadDtv {
    ptr: NonNull<DtvHeader>,
}

// SAFETY: Moving the owner transfers the allocation and all its TLS blocks.
// The default runtime only publishes borrowed pointers within the owning thread.
unsafe impl Send for ThreadDtv {}

impl ThreadDtv {
    /// Allocates an empty per-thread DTV with an initialized header.
    pub fn new() -> Self {
        let layout = Self::layout(0);
        let allocation =
            NonNull::new(unsafe { alloc(layout) }).unwrap_or_else(|| handle_alloc_error(layout));
        let ptr = allocation.cast::<DtvHeader>();
        unsafe {
            ptr.as_ptr().write(EMPTY_DTV);
        }
        Self { ptr }
    }

    fn layout(len: usize) -> Layout {
        let slots = Layout::array::<DtvSlot>(len).expect("TLS DTV capacity overflow");
        let (layout, offset) = Layout::new::<DtvHeader>().extend(slots).unwrap();
        debug_assert_eq!(offset, SLOTS_OFFSET);
        layout.pad_to_align()
    }

    #[allow(dead_code)]
    fn into_raw(self) -> *mut DtvHeader {
        let ptr = self.ptr.as_ptr();
        core::mem::forget(self);
        ptr
    }

    // SAFETY: The pointer must transfer sole ownership of a complete allocation
    // created by this type, with its full provenance and initialized slot count.
    #[allow(dead_code)]
    unsafe fn from_raw(ptr: *mut DtvHeader) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    fn len(&self) -> usize {
        unsafe { self.ptr.as_ref() }.len
    }

    fn slots_mut(&mut self) -> &mut [DtvSlot] {
        // Derive the trailing slice from the allocation pointer, never from a
        // reference to the fixed-size header or its zero-length array field.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.ptr
                    .as_ptr()
                    .cast::<u8>()
                    .add(SLOTS_OFFSET)
                    .cast::<DtvSlot>(),
                self.len(),
            )
        }
    }

    /// Returns the registry generation represented by this DTV.
    #[inline]
    pub fn generation(&self) -> usize {
        unsafe { self.ptr.as_ref() }.generation
    }

    fn ensure_len(&mut self, len: usize) {
        let old_len = self.len();
        if old_len >= len {
            return;
        }
        let capacity = len
            .checked_next_power_of_two()
            .expect("TLS DTV capacity overflow")
            .max(4);
        let old_layout = Self::layout(old_len);
        let new_layout = Self::layout(capacity);
        // Alignment is unchanged. On failure the owner still holds the old
        // allocation; after success initialization below cannot unwind.
        let allocation = NonNull::new(unsafe {
            realloc(self.ptr.as_ptr().cast(), old_layout, new_layout.size())
        })
        .unwrap_or_else(|| handle_alloc_error(new_layout));
        self.ptr = allocation.cast();
        unsafe {
            let slots = allocation.as_ptr().add(SLOTS_OFFSET).cast::<DtvSlot>();
            for index in old_len..capacity {
                slots.add(index).write(DtvSlot::EMPTY);
            }
            self.ptr.as_mut().len = capacity;
        }
    }

    /// Discards blocks whose full IDs are absent from the associated registry.
    /// Hold the registry's read lock through this call when it is shared.
    /// This only frees TLS blocks; it does not retain owners or invoke providers.
    pub fn sync(&mut self, registry: &TlsRegistry) {
        if self.generation() == registry.generation() {
            return;
        }
        self.ensure_len(registry.slot_count());
        for slot in self.slots_mut() {
            if !slot.id.is_reserved() && !registry.contains(slot.id) {
                *slot = DtvSlot::EMPTY;
            }
        }
        unsafe { self.ptr.as_mut() }.generation = registry.generation();
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
        self.ensure_len(index + 1);
        let ptr = block.ptr;
        self.slots_mut()[index] = DtvSlot { id: mod_id, block };
        Ok(ptr)
    }

    /// Returns an already allocated dynamic block from the local cache.
    ///
    /// This does not check the registry generation or whether the module is still
    /// registered. Use [`Self::lookup`] to check a generation, or [`Self::sync`]
    /// to remove blocks for unregistered modules. The pointer retains no ownership
    /// and must not be used after the block is replaced, removed, or dropped.
    #[inline]
    pub fn get(&self, mod_id: TlsModuleId) -> Option<NonNull<u8>> {
        unsafe { DtvHeader::get(self.ptr.as_ptr(), mod_id) }
    }

    /// Queries a cached block relative to a registry generation.
    ///
    /// `generation` must come from the same registry used with [`Self::sync`].
    /// A version mismatch returns [`DtvLookup::Stale`] even if a local block
    /// exists. This method does not lock, synchronize, or allocate storage.
    ///
    /// A hit is valid only relative to the supplied generation; it does not keep
    /// the registry unchanged or retain the module or block. The caller must
    /// uphold the module and thread lifetimes and stop using the pointer before
    /// the block is replaced, removed by synchronization, or dropped.
    #[inline]
    pub fn lookup(&self, mod_id: TlsModuleId, generation: usize) -> DtvLookup {
        unsafe { DtvHeader::lookup(self.ptr.as_ptr(), mod_id, generation) }
    }
}

impl Default for ThreadDtv {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ThreadDtv {
    fn drop(&mut self) {
        let layout = Self::layout(self.len());
        // The runtime withdraws published pointers before dropping this owner.
        // The zero-length field owns no slots: drop the actual trailing slice,
        // then release the entire allocation with its original layout.
        unsafe {
            core::ptr::drop_in_place(self.slots_mut());
            dealloc(self.ptr.as_ptr().cast(), layout);
        }
    }
}

/// Result of querying a DTV cache with [`ThreadDtv::lookup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtvLookup {
    /// No matching allocated block is available.
    Missing,
    /// The DTV generation differs from the requested registry generation.
    Stale,
    /// A matching block exists. The pointer does not retain its ownership.
    Found(NonNull<u8>),
}

cfg_if::cfg_if! {
    if #[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))] {
        mod pthread {
            //! The pthread key owns one complete DTV table. Native TLS caches
            //! only its borrowed header pointer. Updates temporarily transfer
            //! ownership to a guard; the key contains UPDATING until publication.
            //! Reclamation remains delayed to the second destructor round.

            use super::{DtvHeader, DtvLookup, EMPTY_DTV, Result, ThreadDtv, TlsError, TlsModuleId};
            use core::{cell::Cell, ffi::c_void, mem::ManuallyDrop};

            const RETIRING: usize = 1;
            const DESTROYED: *mut DtvHeader = core::ptr::without_provenance_mut(1);
            const UPDATING: *mut DtvHeader = core::ptr::without_provenance_mut(2);
            const _: () = assert!(core::mem::align_of::<DtvHeader>() > 2);

            // EMPTY_DTV is a real immutable zero-length header, not a nullable
            // pointer. The hot path needs only generation, bounds and full-ID checks.
            std::thread_local! {
                static DTV_TABLE: Cell<*const DtvHeader> = const { Cell::new(&EMPTY_DTV) };
            }

            fn publish_table(ptr: *const DtvHeader) {
                let _ = DTV_TABLE.try_with(|table| table.set(ptr));
            }

            // The key lives for the runtime's lifetime. Failed creation can be retried.
            static KEY: spin::Once<libc::pthread_key_t> = spin::Once::new();

            pub(in crate::tls) fn ensure_supported() -> Result<()> {
                KEY.try_call_once(|| {
                    let mut key = 0;
                    let code = unsafe { libc::pthread_key_create(&mut key, Some(destroy)) };
                    if code != 0 {
                        return Err(TlsError::ThreadStorageFailed { code }.into());
                    }
                    Ok(key)
                }).map(|_| ())
            }

            fn rearm(value: *mut DtvHeader) {
                let code = unsafe { libc::pthread_setspecific(*KEY.get().unwrap(), value.cast()) };
                if code != 0 {
                    // Losing the ownership or lifecycle marker could double-free
                    // or resurrect a table. No caller can recover from that state.
                    std::process::abort();
                }
            }

            unsafe extern "C" fn destroy(value: *mut c_void) {
                let ptr = value.cast::<DtvHeader>();
                if ptr == DESTROYED {
                    return;
                }
                if ptr == UPDATING {
                    std::process::abort();
                }
                if ptr.addr() & RETIRING == 0 {
                    rearm(ptr.map_addr(|addr| addr | RETIRING));
                    return;
                }
                let ptr = ptr.map_addr(|addr| addr & !RETIRING);
                // Unpublish before running any allocation destructors. Non-allocating
                // reentrant queries see no block, and new updates are rejected.
                rearm(DESTROYED);
                publish_table(&EMPTY_DTV);
                // SAFETY: The key held sole ownership. Stripping the tag preserves
                // allocation provenance, and this consumes that ownership once.
                unsafe { drop(ThreadDtv::from_raw(ptr)) };
            }

            #[inline]
            pub(in crate::tls) fn lookup_dtv<const CACHED_ONLY: bool>(
                mod_id: TlsModuleId,
                generation: usize,
            ) -> DtvLookup {
                // The published table is immutable until the lookup returns.
                let cached = DTV_TABLE.try_with(|table| unsafe {
                    DtvHeader::lookup(table.get(), mod_id, generation)
                }).unwrap_or(DtvLookup::Missing);
                match cached {
                    hit @ DtvLookup::Found(_) => return hit,
                    other if CACHED_ONLY => return other,
                    _ => {}
                }
                // The pthread key remains authoritative if std TLS is unavailable.
                let Some(&key) = KEY.get() else { return DtvLookup::Missing; };
                let ptr = unsafe { libc::pthread_getspecific(key) }.cast::<DtvHeader>();
                if ptr.addr() <= UPDATING.addr() {
                    return DtvLookup::Missing;
                }
                let ptr = ptr.map_addr(|addr| addr & !RETIRING);
                publish_table(ptr);
                unsafe { DtvHeader::lookup(ptr, mod_id, generation) }
            }

            struct Update {
                dtv: ManuallyDrop<ThreadDtv>,
                retiring: bool,
            }

            impl Drop for Update {
                fn drop(&mut self) {
                    // Transfer the whole allocation back to the pthread key.
                    let table = unsafe { ManuallyDrop::take(&mut self.dtv) };
                    let ptr = table.into_raw();
                    // Preserve the destructor round even when a callback grows the table.
                    let tagged = if self.retiring {
                        ptr.map_addr(|addr| addr | RETIRING)
                    } else {
                        ptr
                    };
                    rearm(tagged);
                    publish_table(ptr);
                }
            }

            pub(in crate::tls) fn with_dtv<R>(f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
                let key = *KEY.get().expect("managed TLS must be registered before resolving it");
                let ptr = unsafe { libc::pthread_getspecific(key) }.cast::<DtvHeader>();
                assert_ne!(ptr, DESTROYED, "managed TLS thread storage has been destroyed");
                assert_ne!(ptr, UPDATING, "reentrant managed TLS storage update");
                let retiring = ptr.addr() & RETIRING != 0;
                let ptr = ptr.map_addr(|addr| addr & !RETIRING);
                // Withdraw both published references before constructing a mutable
                // owner. A rejected nested update cannot take or republish this table.
                rearm(UPDATING);
                publish_table(&EMPTY_DTV);
                let mut update = Update {
                    // SAFETY: The key transferred its sole ownership to this guard.
                    dtv: ManuallyDrop::new(if ptr.is_null() {
                        ThreadDtv::new()
                    } else {
                        unsafe { ThreadDtv::from_raw(ptr) }
                    }),
                    retiring,
                };
                // The closure cannot return a reference borrowing the table. The
                // guard republishes the current allocation, also after unwinding.
                f(&mut update.dtv)
            }
        }

        pub(super) use pthread::{ensure_supported, lookup_dtv, with_dtv};
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
            panic!("managed TLS thread storage requires std on Linux/Android")
        }
    }
}
