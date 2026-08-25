use std::path::Path;

use elf_loader::{Loader, Relocator, image::LoadedObject};

use crate::fixtures::{Riscv64Fixtures, riscv64};

const LOADER: Loader = Loader::new();

fn fixtures() -> &'static Riscv64Fixtures {
    riscv64()
}

fn load(path: &Path) -> LoadedObject {
    Relocator::new()
        .run(
            LOADER
                .load_object(path.to_str().expect("fixture path must be valid UTF-8"))
                .expect("failed to load RISC-V object fixture"),
        )
        .relocate()
        .expect("failed to relocate RISC-V object fixture")
}

#[test]
fn resolves_external_symbols() {
    let fixtures = fixtures();
    let b = load(&fixtures.b);
    let a = Relocator::new()
        .run(
            LOADER
                .load_object(
                    fixtures
                        .a
                        .to_str()
                        .expect("fixture path must be valid UTF-8"),
                )
                .expect("failed to load a.o"),
        )
        .modules([&b])
        .relocate()
        .expect("failed to relocate a.o");

    let a_fn = unsafe {
        a.get::<extern "C" fn() -> i32>("a")
            .expect("missing symbol a")
    };
    let b_fn = unsafe {
        b.get::<extern "C" fn() -> i32>("b")
            .expect("missing symbol b")
    };
    assert_eq!(b_fn(), 41);
    assert_eq!(a_fn(), 83);
}

#[test]
fn relocates_calls() {
    let object = load(&fixtures().call);
    let call = unsafe {
        object
            .get::<extern "C" fn(i32) -> i32>("call_test")
            .expect("missing call_test")
    };

    assert_eq!(call(5), 210);
}

#[test]
fn relocates_globals() {
    let object = load(&fixtures().globals);
    let read = unsafe {
        object
            .get::<extern "C" fn() -> i32>("read_globals")
            .expect("missing read_globals")
    };
    let get_ptr = unsafe {
        object
            .get::<extern "C" fn() -> *mut i32>("get_global_ptr")
            .expect("missing get_global_ptr")
    };
    let modify = unsafe {
        object
            .get::<extern "C" fn(i32) -> i32>("modify_through_pointer")
            .expect("missing modify_through_pointer")
    };

    assert_eq!(read(), 141);
    assert_eq!(unsafe { *get_ptr() }, 42);
    assert_eq!(modify(8), 50);
}

#[test]
fn relocates_hi_lo_pairs() {
    let object = load(&fixtures().hi_lo);
    let load_value = unsafe {
        object
            .get::<extern "C" fn(i32) -> i32>("test_hi20_load")
            .expect("missing test_hi20_load")
    };
    let store_value = unsafe {
        object
            .get::<extern "C" fn(i32, i32)>("test_hi20_store")
            .expect("missing test_hi20_store")
    };
    let load_external = unsafe {
        object
            .get::<extern "C" fn(i32) -> i32>("test_extern_array")
            .expect("missing test_extern_array")
    };

    store_value(50, 123);
    assert_eq!(load_value(50), 123);
    assert_eq!(load_external(0), 0);
}

#[test]
fn relocates_pointers() {
    let object = load(&fixtures().pointers);
    let call = unsafe {
        object
            .get::<extern "C" fn(i32, i32) -> i32>("call_through_table")
            .expect("missing call_through_table")
    };
    let sum = unsafe {
        object
            .get::<extern "C" fn() -> i32>("sum_through_ptrs")
            .expect("missing sum_through_ptrs")
    };

    assert_eq!(call(0, 10), 11);
    assert_eq!(call(1, 10), 20);
    assert_eq!(call(2, 10), 9);
    assert_eq!(sum(), 60);
}
