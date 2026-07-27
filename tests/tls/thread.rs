use std::{
    sync::{Arc, Barrier},
    thread,
};

use crate::support::{FIRST, SECOND, scenario};

#[test]
fn isolates_threads() {
    let first = scenario().helper(FIRST);
    let second = scenario().helper(SECOND);
    let count = 4;
    let barrier = Arc::new(Barrier::new(count));
    let threads = (0..count)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let (first, second) = (first(), second());
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
