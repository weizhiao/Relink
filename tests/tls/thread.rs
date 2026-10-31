use std::{
    sync::{Arc, Barrier},
    thread,
};

use crate::support::{FIRST, SECOND, scenario};
use elf_loader::{Module, tls::DefaultTlsResolver};

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
