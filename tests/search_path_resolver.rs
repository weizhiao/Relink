#![cfg(not(windows))]

#[path = "../examples/common/mod.rs"]
mod fixture_support;

use elf_loader::linker::{LinkContext, Linker, SearchPathResolver};

#[test]
fn loads_fixture_chain() {
    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<String, ()>::new();

    let loaded = Linker::new()
        .resolver(SearchPathResolver::new())
        .load(&mut context, fixtures.libc_str().to_owned())
        .unwrap();

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert_eq!(c(), 3);
}

#[test]
fn scan_first_loads_fixture_chain() {
    let fixtures = fixture_support::ensure_all();
    let mut context = LinkContext::<String, ()>::new();

    let loaded = Linker::new()
        .resolver(SearchPathResolver::new())
        .load_scan_first(&mut context, fixtures.libc_str().to_owned())
        .unwrap();

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    assert_eq!(c(), 3);
}
