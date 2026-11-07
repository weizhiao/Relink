use std::{
    sync::{Arc, Barrier},
    thread,
};

use crate::support::{FIRST, SECOND, scenario};
use elf_loader::{Module, tls::DefaultTlsResolver};

#[test]
fn cached_blocks_survive_registry_changes() {
    use elf_loader::tls::{TlsInfo, TlsRequest, TlsResolver, TlsTemplate};

    let resolver = DefaultTlsResolver::new();
    let info = TlsInfo {
        vaddr: 0,
        filesz: 4,
        memsz: 4,
        align: 4,
    };
    let first = resolver.register(info, TlsRequest::Dynamic).unwrap();
    let first_id = first.module().mod_id();
    resolver
        .publish(TlsTemplate::new(&7u32.to_ne_bytes()), first_id)
        .unwrap();
    assert!(DefaultTlsResolver::get_ptr_if_allocated(first_id).is_none());
    let base = DefaultTlsResolver::get_ptr(first_id).unwrap();

    let second = resolver.register(info, TlsRequest::Dynamic).unwrap();
    let second_id = second.module().mod_id();
    resolver
        .publish(TlsTemplate::new(&9u32.to_ne_bytes()), second_id)
        .unwrap();
    // Synchronization must preserve existing blocks and leave missing ones unallocated.
    assert_eq!(
        DefaultTlsResolver::get_ptr_if_allocated(first_id),
        Some(base)
    );
    assert!(DefaultTlsResolver::get_ptr_if_allocated(second_id).is_none());
    assert!(DefaultTlsResolver::get_ptr(second_id).is_some());
    drop(second);
    assert!(DefaultTlsResolver::get_ptr_if_allocated(second_id).is_none());
    assert_eq!(
        DefaultTlsResolver::get_ptr_if_allocated(first_id),
        Some(base)
    );
    assert_eq!(unsafe { base.cast::<u32>().read() }, 7);
    drop(first);
    assert!(DefaultTlsResolver::get_ptr_if_allocated(first_id).is_none());
}

#[test]
fn isolates_threads() {
    let first = scenario().helper(FIRST);
    let second = scenario().helper(SECOND);
    let mod_id = scenario().provider().tls().unwrap().mod_id();
    let count = 4;
    // Start another group after joining: reused OS thread identities must not
    // inherit a previous thread's DTV or modified template bytes.
    for _ in 0..2 {
        let barrier = Arc::new(Barrier::new(count));
        let threads = (0..count)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    assert!(DefaultTlsResolver::get_ptr_if_allocated(mod_id).is_none());
                    let (first, second) = (first(), second());
                    assert!(DefaultTlsResolver::get_ptr_if_allocated(mod_id).is_some());
                    unsafe {
                        assert_eq!((*first, *second), (0xDDCCBBAA, 0x44332211));
                        barrier.wait();
                        (*first, *second) = (index as u32 + 0x100, index as u32 + 0x200);
                        barrier.wait();
                        assert_eq!(
                            (*first, *second),
                            (index as u32 + 0x100, index as u32 + 0x200)
                        );
                    }
                })
            })
            .collect::<Vec<_>>();

        for thread in threads {
            thread.join().expect("TLS thread panicked");
        }
    }
}
