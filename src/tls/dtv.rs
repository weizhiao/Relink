//! Per-thread TLS address cache and separately owned dynamic blocks.

use super::{TlsInfo, TlsModuleId, TlsRegistry};
use crate::{Result, TlsError};
use alloc::{
    alloc::{alloc, dealloc, handle_alloc_error, realloc},
    collections::BTreeMap,
};
use core::{alloc::Layout, ptr::NonNull};

// Cold ownership metadata, separate from the address lookup slots.
#[repr(C)]
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
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct DtvSlot {
    id: TlsModuleId,
    base: NonNull<u8>,
}

impl DtvSlot {
    const EMPTY: Self = Self {
        id: TlsModuleId::RESERVED,
        base: NonNull::dangling(),
    };
}

// Slot zero holds the header; module slot numbers index the allocation directly.
// The length includes the header. Module capacity is an even power of two, so
// the length is always odd (including EMPTY_DTV's length of one). Its low slot
// bits can therefore never match an ID that indexes slot zero.
#[derive(Clone, Copy)]
#[repr(C)]
struct DtvHeader {
    len: usize,
    generation: usize,
}

#[repr(C)]
union DtvEntry {
    header: DtvHeader,
    slot: DtvSlot,
}

const EMPTY_DTV: DtvEntry = DtvEntry {
    header: DtvHeader {
        len: 1,
        generation: 0,
    },
};

impl DtvEntry {
    #[inline]
    // The pointer must retain provenance for the whole allocation, not be
    // derived from a reference narrowed to the header. The table must be live
    // and immutable for the duration of this leaf lookup.
    unsafe fn get(table: *const Self, mod_id: TlsModuleId) -> Option<NonNull<u8>> {
        let index = mod_id.get() & TlsModuleId::SLOT_MASK;
        if index >= unsafe { (*table).header.len } {
            return None;
        }
        // Read only the ID field, never the whole slot: at index zero the
        // first word is an odd header length, a valid TlsModuleId bit pattern
        // that cannot match an ID with zero low slot bits. Thus only real slots
        // reach the base load, without interpreting generation as a pointer.
        let entry = unsafe { table.add(index) };
        if unsafe { (*entry).slot.id } != mod_id {
            return None;
        }
        Some(unsafe { (*entry).slot.base })
    }

    #[inline]
    unsafe fn lookup(table: *const Self, mod_id: TlsModuleId, generation: usize) -> DtvLookup {
        if unsafe { (*table).header.generation } != generation {
            return DtvLookup::Stale;
        }
        unsafe { Self::get(table, mod_id) }.map_or(DtvLookup::Missing, DtvLookup::Found)
    }
}

/// Caches per-thread TLS addresses and owns managed dynamic blocks separately.
///
/// The address table contains a header in slot zero followed by address slots,
/// indexed by their one-based ABI slot numbers. A separate ownership map contains
/// only allocated dynamic blocks, keyed by full module IDs. Static and external
/// addresses are borrowed and require no entries in that map. This type does not
/// define an architecture's ABI-visible DTV layout and retains no module owners.
/// IDs must use [`super::TlsRegistry`]'s slot/incarnation encoding. Resolvers
/// with another ID format must provide their own thread storage.
pub struct ThreadDtv {
    ptr: Option<NonNull<DtvEntry>>,
    blocks: BTreeMap<TlsModuleId, TlsBlock>,
}

// SAFETY: Moving the owner transfers the allocation and all its TLS blocks.
// The default runtime only publishes borrowed pointers within the owning thread.
unsafe impl Send for ThreadDtv {}

impl ThreadDtv {
    /// Creates an empty DTV. Storage is allocated when slots are first needed.
    pub const fn new() -> Self {
        Self {
            ptr: None,
            blocks: BTreeMap::new(),
        }
    }

    fn as_ptr(&self) -> *const DtvEntry {
        self.ptr.map_or(&EMPTY_DTV, |ptr| ptr.as_ptr().cast_const())
    }

    fn layout(len: usize) -> Layout {
        let entries = len.checked_add(1).expect("TLS DTV capacity overflow");
        Layout::array::<DtvEntry>(entries).expect("TLS DTV capacity overflow")
    }

    fn len(&self) -> usize {
        // The trailing slice contains module slots only, excluding the header.
        unsafe { (*self.as_ptr()).header.len - 1 }
    }

    fn slots_mut(&mut self) -> &mut [DtvEntry] {
        let Some(ptr) = self.ptr else {
            return &mut [];
        };
        // Derive the slice from the complete allocation, not a header reference.
        unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr().add(1), self.len()) }
    }

    /// Returns the registry generation represented by this DTV.
    #[inline]
    pub fn generation(&self) -> usize {
        unsafe { (*self.as_ptr()).header.generation }
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
        let new_layout = Self::layout(capacity);
        let old_layout = Self::layout(old_len);
        // Allocate the header and slots together on first use. Later growth keeps
        // the same alignment. On failure the owner retains its old allocation;
        // after success initialization below cannot unwind.
        let allocation = NonNull::new(unsafe {
            if let Some(ptr) = self.ptr {
                realloc(ptr.as_ptr().cast(), old_layout, new_layout.size())
            } else {
                alloc(new_layout)
            }
        })
        .unwrap_or_else(|| handle_alloc_error(new_layout));
        let ptr = allocation.cast::<DtvEntry>();
        unsafe {
            if self.ptr.is_none() {
                ptr.as_ptr().write(EMPTY_DTV);
            }
            let slots = ptr.as_ptr().add(1);
            for index in old_len..capacity {
                slots.add(index).write(DtvEntry {
                    slot: DtvSlot::EMPTY,
                });
            }
            (*ptr.as_ptr()).header.len = capacity + 1;
        }
        self.ptr = Some(ptr);
    }

    /// Discards addresses and owned blocks whose full IDs are absent from the registry.
    /// Hold the registry's read lock through this call when it is shared.
    /// This only frees TLS blocks; it does not retain owners or invoke providers.
    pub fn sync(&mut self, registry: &TlsRegistry) {
        if self.generation() == registry.generation() {
            return;
        }
        self.ensure_len(registry.slot_count());
        for entry in self.slots_mut() {
            // The slice excludes the header; each entry contains a valid slot.
            let slot = unsafe { &mut entry.slot };
            if !slot.id.is_reserved() && !registry.contains(slot.id) {
                *slot = DtvSlot::EMPTY;
            }
        }
        self.blocks.retain(|id, _| registry.contains(*id));
        // A changed registry has slots, so ensure_len installed an allocation.
        unsafe { (*self.ptr.unwrap().as_ptr()).header.generation = registry.generation() };
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
        // Replacing an incarnation releases only its owned dynamic block.
        let old_id = unsafe { self.slots_mut()[index].slot.id };
        self.blocks.remove(&old_id);
        self.blocks.insert(mod_id, block);
        self.slots_mut()[index] = DtvEntry {
            slot: DtvSlot {
                id: mod_id,
                base: ptr,
            },
        };
        Ok(ptr)
    }

    /// Caches a borrowed address without taking ownership of its storage.
    ///
    /// # Safety
    /// The address must identify this thread's block for the live `mod_id` and
    /// remain valid while that registration and thread are alive. The caller must
    /// validate registry membership before publishing the cache entry. A new
    /// incarnation must not borrow storage owned by the slot it replaces.
    /// Repeated calls for the same ID must supply the same base address.
    pub unsafe fn cache(&mut self, mod_id: TlsModuleId, base: NonNull<u8>) -> Result<()> {
        if let Some(cached) = self.get(mod_id) {
            // Managed resolution already installed its owner. Do not discard it.
            debug_assert_eq!(cached, base);
            return Ok(());
        }
        let index = mod_id.slot().ok_or(TlsError::InvalidModuleId { mod_id })?;
        self.ensure_len(index + 1);
        let old_id = unsafe { self.slots_mut()[index].slot.id };
        self.blocks.remove(&old_id);
        self.slots_mut()[index] = DtvEntry {
            slot: DtvSlot { id: mod_id, base },
        };
        Ok(())
    }

    /// Returns a cached address, whether owned or borrowed.
    ///
    /// This does not check the registry generation or whether the module is still
    /// registered. Use [`Self::lookup`] to check a generation, or [`Self::sync`]
    /// to remove blocks for unregistered modules. The pointer retains no ownership
    /// and must not be used after the block is replaced, removed, or dropped.
    #[inline]
    pub fn get(&self, mod_id: TlsModuleId) -> Option<NonNull<u8>> {
        unsafe { DtvEntry::get(self.as_ptr(), mod_id) }
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
        unsafe { DtvEntry::lookup(self.as_ptr(), mod_id, generation) }
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
        let Some(ptr) = self.ptr else {
            return;
        };
        let layout = Self::layout(self.len());
        // The runtime withdraws published pointers before dropping this owner.
        // The ownership map is dropped separately. Borrowed addresses need no cleanup.
        unsafe {
            dealloc(ptr.as_ptr().cast(), layout);
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
            //! The pthread key owns the thread state. Native TLS caches
            //! only its borrowed header pointer. Updates temporarily transfer
            //! ownership to a guard; the key contains UPDATING until publication.
            //! Reclamation remains delayed to the second destructor round.

            use super::{DtvEntry, DtvLookup, EMPTY_DTV, NonNull, Result, ThreadDtv, TlsError, TlsModuleId};
            use core::{cell::Cell, ffi::c_void, mem::ManuallyDrop};
            use alloc::boxed::Box;

            const RETIRING: usize = 1;
            const DESTROYED: *mut ThreadDtv = core::ptr::without_provenance_mut(1);
            const UPDATING: *mut ThreadDtv = core::ptr::without_provenance_mut(2);
            const _: () = assert!(core::mem::align_of::<ThreadDtv>() > 2);

            // A valid immutable header is always published, including before
            // the first module slot is allocated.
            std::thread_local! {
                static DTV_TABLE: Cell<*const DtvEntry> = const { Cell::new(&EMPTY_DTV) };
            }

            fn publish_table(ptr: *const DtvEntry) {
                let ptr = if ptr.is_null() { &EMPTY_DTV } else { ptr };
                let _ = DTV_TABLE.try_with(|table| table.set(ptr));
            }

            // The key lives for the runtime's lifetime. Failed creation can be retried.
            static KEY: spin::Once<libc::pthread_key_t> = spin::Once::new();

            pub(in crate::tls) fn ensure_thread_storage() -> Result<()> {
                KEY.try_call_once(|| {
                    let mut key = 0;
                    let code = unsafe { libc::pthread_key_create(&mut key, Some(destroy)) };
                    if code != 0 {
                        return Err(TlsError::ThreadStorageFailed { code }.into());
                    }
                    Ok(key)
                }).map(|_| ())
            }

            fn rearm(value: *mut ThreadDtv) {
                let code = unsafe { libc::pthread_setspecific(*KEY.get().unwrap(), value.cast()) };
                if code != 0 {
                    // Losing the ownership or lifecycle marker could double-free
                    // or resurrect a table. No caller can recover from that state.
                    std::process::abort();
                }
            }

            unsafe extern "C" fn destroy(value: *mut c_void) {
                let ptr = value.cast::<ThreadDtv>();
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
                unsafe { drop(Box::from_raw(ptr)) };
            }

            #[inline]
            pub(in crate::tls) fn lookup_cached(mod_id: TlsModuleId) -> Option<NonNull<u8>> {
                // ELF callers retain their registration. Full IDs are never
                // reused, so unrelated registry changes cannot invalidate a hit.
                DTV_TABLE.try_with(|table| unsafe {
                    DtvEntry::get(table.get(), mod_id)
                }).ok().flatten()
            }

            #[inline]
            pub(in crate::tls) fn lookup_dtv(
                mod_id: TlsModuleId,
                generation: usize,
                synchronize: impl FnOnce(&mut ThreadDtv),
            ) -> Option<NonNull<u8>> {
                // The published table is immutable until the lookup returns.
                let cached = DTV_TABLE.try_with(|table| unsafe {
                    DtvEntry::lookup(table.get(), mod_id, generation)
                }).unwrap_or(DtvLookup::Missing);
                if let DtvLookup::Found(base) = cached {
                    return Some(base);
                }
                // The pthread key remains authoritative if std TLS is unavailable.
                let key = *KEY.get()?;
                let ptr = unsafe { libc::pthread_getspecific(key) }.cast::<ThreadDtv>();
                if ptr.addr() <= UPDATING.addr() {
                    return None;
                }
                let ptr = ptr.map_addr(|addr| addr & !RETIRING);
                let table = unsafe { (*ptr).as_ptr() };
                publish_table(table);
                let lookup = unsafe { DtvEntry::lookup(table, mod_id, generation) };
                // End the immutable lookup before withdrawing the table and
                // lending its owner to the synchronization callback.
                match lookup {
                    DtvLookup::Found(base) => Some(base),
                    DtvLookup::Missing => None,
                    DtvLookup::Stale => with_dtv(|dtv| {
                        synchronize(dtv);
                        dtv.get(mod_id)
                    }),
                }
            }

            struct Update {
                dtv: ManuallyDrop<Box<ThreadDtv>>,
                retiring: bool,
            }

            impl Drop for Update {
                fn drop(&mut self) {
                    // Transfer the state back to the key; publish only the address table.
                    let state = unsafe { ManuallyDrop::take(&mut self.dtv) };
                    let table = state.as_ptr();
                    let ptr = Box::into_raw(state);
                    // Preserve the destructor round even when a callback grows the table.
                    let tagged = if self.retiring && !ptr.is_null() {
                        ptr.map_addr(|addr| addr | RETIRING)
                    } else {
                        ptr
                    };
                    rearm(tagged);
                    publish_table(table);
                }
            }

            pub(in crate::tls) fn with_dtv<R>(f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
                let key = *KEY.get().expect("TLS must be registered before accessing thread storage");
                let ptr = unsafe { libc::pthread_getspecific(key) }.cast::<ThreadDtv>();
                assert_ne!(ptr, DESTROYED, "TLS thread storage has been destroyed");
                assert_ne!(ptr, UPDATING, "reentrant TLS thread storage update");
                let retiring = ptr.addr() & RETIRING != 0;
                let ptr = ptr.map_addr(|addr| addr & !RETIRING);
                // Withdraw both published references before constructing a mutable
                // owner. A rejected nested update cannot take or republish this table.
                rearm(UPDATING);
                publish_table(&EMPTY_DTV);
                let mut update = Update {
                    // SAFETY: The key transferred its sole ownership to this guard.
                    dtv: ManuallyDrop::new(if ptr.is_null() {
                        Box::new(ThreadDtv::new())
                    } else {
                        unsafe { Box::from_raw(ptr) }
                    }),
                    retiring,
                };
                // The closure cannot return a reference borrowing the table. The
                // guard republishes the current allocation, also after unwinding.
                f(&mut update.dtv)
            }
        }

        pub(super) use pthread::{ensure_thread_storage, lookup_cached, lookup_dtv, with_dtv};
    } else {
        pub(super) fn lookup_cached(_: TlsModuleId) -> Option<NonNull<u8>> {
            None
        }

        pub(super) fn ensure_thread_storage() -> Result<()> {
            Err(TlsError::ResolverUnsupported.into())
        }

        pub(super) fn lookup_dtv(
            _mod_id: TlsModuleId,
            _generation: usize,
            _synchronize: impl FnOnce(&mut ThreadDtv),
        ) -> Option<NonNull<u8>> {
            None
        }

        pub(super) fn with_dtv<R>(_f: impl FnOnce(&mut ThreadDtv) -> R) -> R {
            panic!("managed TLS thread storage requires std on Linux/Android")
        }
    }
}
