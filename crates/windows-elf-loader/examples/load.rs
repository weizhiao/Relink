use std::{collections::HashMap, ffi::CStr};
use windows_elf_loader::WinElfLoader;

fn main() {
    extern "sysv64" fn print(s: *const i8) {
        let s = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        println!("{}", s);
    }
    // Symbols required by dynamic library liba.so
    let mut map = HashMap::new();
    map.insert("print", print as _);
    let pre_find = |name: &str| -> Option<*const ()> { map.get(name).copied() };
    let mut loader: WinElfLoader = WinElfLoader::new();
    // Load and relocate dynamic library liba.so
    let liba = loader
        .load_file(r".\crates\windows-elf-loader\example_dylib\liba.so")
        .unwrap()
        .relocator()
        .post_find_fn(&pre_find)
        .relocate()
        .unwrap();
    // Call function a in liba.so
    let f = unsafe { liba.get::<extern "sysv64" fn() -> i32>("a").unwrap() };
    println!("{}", f());
}
