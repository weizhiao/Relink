use std::{collections::HashMap, ffi::CStr};

use windows_elf_loader::WinElfLoader;

fn main() {
    extern "sysv64" fn print(s: *const i8) {
        let s = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        println!("{}", s);
    }

    let mut map = HashMap::new();
    map.insert("print", print as _);
    let pre_find = |name: &str| -> Option<*const ()> { map.get(name).copied() };
    let mut loader = WinElfLoader::new();
    let liba = loader
        .load_dylib("liba", include_bytes!("../example_dylib/liba.so"))
        .unwrap()
        .relocator()
        .pre_find_fn(pre_find)
        .relocate()
        .unwrap();
    let libb = loader
        .load_dylib("libb", include_bytes!("../example_dylib/libb.so"))
        .unwrap()
        .relocator()
        .pre_find_fn(pre_find)
        .scope([&liba])
        .relocate()
        .unwrap();
    let libc = loader
        .load_dylib("libc", include_bytes!("../example_dylib/libc.so"))
        .unwrap()
        .relocator()
        .pre_find_fn(pre_find)
        .scope([&libb])
        .relocate()
        .unwrap();
    let f = unsafe { liba.get::<extern "sysv64" fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { libb.get::<extern "sysv64" fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { libc.get::<extern "sysv64" fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
}
