use core::str;
use elf_loader::{Loader, input::ElfFile};
use std::collections::HashMap;
use std::sync::Arc;

fn main() {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    fn print(s: &str) {
        println!("{}", s);
    }

    let mut map = HashMap::new();
    map.insert("print", print as *const () as usize);
    let pre_find = Arc::new(move |name: &str| -> Option<*const ()> {
        map.get(name).copied().map(|p| p as *const ())
    });
    let mut loader = Loader::new();
    let object = ElfFile::from_path("target/a.o").unwrap();
    let a = loader
        .load_object(object)
        .unwrap()
        .relocator()
        .pre_find(pre_find.clone())
        .relocate()
        .unwrap();
    let b = loader
        .load_dylib(ElfFile::from_path("target/libb.so").unwrap())
        .unwrap()
        .relocator()
        .pre_find(pre_find.clone())
        .scope([&a])
        .relocate()
        .unwrap();
    let c = loader
        .load_object(ElfFile::from_path("target/c.o").unwrap())
        .unwrap()
        .relocator()
        .pre_find(pre_find.clone())
        .scope([&a])
        .add_scope([&b])
        .relocate()
        .unwrap();
    let f = unsafe { a.get::<extern "C" fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { b.get::<extern "C" fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { c.get::<extern "C" fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
}
