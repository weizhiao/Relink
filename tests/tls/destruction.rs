use crate::support::{FIRST, TlsHelper, scenario};
use elf_loader::{
    Module,
    tls::{DefaultTlsResolver, TlsModuleId},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
};

// Watch one real TLS block, so the test catches leaks from ManuallyDrop as well
// as stale cache entries exposed while its allocator is reclaiming the block.
static WATCHED_BLOCK: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static WATCHED_MODULE: AtomicUsize = AtomicUsize::new(0);
static FREED_BLOCKS: AtomicUsize = AtomicUsize::new(0);
static VISIBLE_DURING_FREE: AtomicBool = AtomicBool::new(false);
static VALUE_AT_EXIT: AtomicUsize = AtomicUsize::new(usize::MAX);
static VALUE_IN_PTHREAD: AtomicUsize = AtomicUsize::new(usize::MAX);
static LATE_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static RESURRECTED: AtomicBool = AtomicBool::new(false);
static INIT_REENTRY: AtomicBool = AtomicBool::new(false);
static VISIBLE_DURING_INIT: AtomicBool = AtomicBool::new(false);

struct TrackingAllocator;

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if CHECK_INIT
            .try_with(|armed| armed.replace(false))
            .unwrap_or(false)
        {
            let mod_id = TlsModuleId::new(WATCHED_MODULE.load(Ordering::Acquire));
            // Non-allocating queries are supported before the owner exists;
            // recursively creating a DTV from this allocator is not supported.
            VISIBLE_DURING_INIT.store(
                DefaultTlsResolver::get_ptr_if_allocated(mod_id).is_some(),
                Ordering::Release,
            );
            INIT_REENTRY.store(true, Ordering::Release);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if WATCHED_BLOCK
            .compare_exchange(
                pointer,
                ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let mod_id = TlsModuleId::new(WATCHED_MODULE.load(Ordering::Acquire));
            VISIBLE_DURING_FREE.store(
                DefaultTlsResolver::get_ptr_if_allocated(mod_id).is_some()
                    || DefaultTlsResolver::get_ptr(mod_id).is_some(),
                Ordering::Release,
            );
            FREED_BLOCKS.fetch_add(1, Ordering::Release);
        }
        unsafe { System.dealloc(pointer, layout) };
    }
}

struct ReadOnExit {
    helper: TlsHelper,
    mod_id: TlsModuleId,
    result: &'static AtomicUsize,
}

impl Drop for ReadOnExit {
    fn drop(&mut self) {
        // Avoid aborting inside the ELF ABI helper if storage was reclaimed too
        // early: leave the sentinel for the parent thread's assertion instead.
        if DefaultTlsResolver::get_ptr_if_allocated(self.mod_id).is_some() {
            let value = unsafe { *(self.helper)() };
            self.result.store(value as usize, Ordering::Release);
        }
    }
}

std::thread_local! {
    static CHECK_INIT: Cell<bool> = const { Cell::new(false) };
    static EARLY: RefCell<Option<ReadOnExit>> = const { RefCell::new(None) };
}

#[test]
fn dtv_outlives_earlier_host_tls_and_is_reclaimed_at_thread_exit() {
    let helper = scenario().helper(FIRST);
    let mod_id = scenario().provider().tls().unwrap().mod_id();
    struct Cleanup {
        read: Option<ReadOnExit>,
        mod_id: TlsModuleId,
        key: libc::pthread_key_t,
        round: usize,
    }
    unsafe extern "C" fn pthread_cleanup(pointer: *mut core::ffi::c_void) {
        let mut cleanup = unsafe { Box::from_raw(pointer.cast::<Cleanup>()) };
        if cleanup.round == 1 {
            drop(cleanup.read.take());
        } else {
            // The DTV has now been reclaimed. Neither query nor allocating
            // lookup may expose the old block or initialize a replacement.
            LATE_CALLBACKS.fetch_add(1, Ordering::Release);
            if DefaultTlsResolver::get_ptr_if_allocated(cleanup.mod_id).is_some()
                || DefaultTlsResolver::get_ptr(cleanup.mod_id).is_some()
            {
                RESURRECTED.store(true, Ordering::Release);
            }
        }
        if cleanup.round < 4 {
            cleanup.round += 1;
            let code = unsafe {
                libc::pthread_setspecific(cleanup.key, ptr::from_mut(&mut *cleanup).cast())
            };
            if code != 0 {
                std::process::abort();
            }
            let _ = Box::into_raw(cleanup);
        }
    }
    // glibc visits this later-created key after the resolver's key in the first
    // destructor round, as can happen with a loaded Rust runtime's cleanup key.
    let mut key = 0;
    assert_eq!(
        unsafe { libc::pthread_key_create(&mut key, Some(pthread_cleanup)) },
        0
    );
    std::thread::spawn(move || {
        // This destructor is registered BEFORE the first access to library TLS.
        EARLY.with(|slot| {
            *slot.borrow_mut() = Some(ReadOnExit {
                helper,
                mod_id,
                result: &VALUE_AT_EXIT,
            })
        });
        WATCHED_MODULE.store(mod_id.get(), Ordering::Release);
        CHECK_INIT.with(|armed| armed.set(true));
        let pointer = helper();
        unsafe { *pointer = 99 };
        WATCHED_BLOCK.store(pointer.cast(), Ordering::Release);
        let mut cleanup = Box::new(Cleanup {
            read: Some(ReadOnExit {
                helper,
                mod_id,
                result: &VALUE_IN_PTHREAD,
            }),
            mod_id,
            key,
            round: 1,
        });
        assert_eq!(
            unsafe { libc::pthread_setspecific(key, ptr::from_mut(&mut *cleanup).cast()) },
            0
        );
        let _ = Box::into_raw(cleanup);
    })
    .join()
    .expect("TLS worker panicked");
    assert_eq!(unsafe { libc::pthread_key_delete(key) }, 0);

    assert_eq!(VALUE_AT_EXIT.load(Ordering::Acquire), 99);
    assert_eq!(VALUE_IN_PTHREAD.load(Ordering::Acquire), 99);
    assert_eq!(FREED_BLOCKS.load(Ordering::Acquire), 1);
    assert!(WATCHED_BLOCK.load(Ordering::Acquire).is_null());
    assert!(!VISIBLE_DURING_FREE.load(Ordering::Acquire));
    assert_eq!(LATE_CALLBACKS.load(Ordering::Acquire), 3);
    assert!(!RESURRECTED.load(Ordering::Acquire));
    assert!(INIT_REENTRY.load(Ordering::Acquire));
    assert!(!VISIBLE_DURING_INIT.load(Ordering::Acquire));
}
