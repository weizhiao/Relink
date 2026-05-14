use std::ffi::CStr;

use elf_loader::image::{ModuleHandle, SyntheticModule, SyntheticSymbol};
use windows_elf_loader::WinElfLoader;

fn main() {
    extern "sysv64" fn print(s: *const i8) {
        let s = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        println!("{}", s);
    }

    let host = ModuleHandle::from(SyntheticModule::new(
        "__host",
        [SyntheticSymbol::function("print", print as *const ())],
    ));
    let mut loader = WinElfLoader::new();
    let liba = loader
        .load_file(r".\crates\windows-elf-loader\example_dylib\liba.so")
        .unwrap()
        .relocator()
        .scope([host.clone()])
        .relocate()
        .unwrap();
    let libb = loader
        .load_file(r".\crates\windows-elf-loader\example_dylib\libb.so")
        .unwrap()
        .relocator()
        .scope([host.clone(), ModuleHandle::from(&liba)])
        .relocate()
        .unwrap();
    let libc = loader
        .load_file(r".\crates\windows-elf-loader\example_dylib\libc.so")
        .unwrap()
        .relocator()
        .scope([host.clone(), ModuleHandle::from(&libb)])
        .relocate()
        .unwrap();
    let f = unsafe { liba.get::<extern "sysv64" fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { libb.get::<extern "sysv64" fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { libc.get::<extern "sysv64" fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
}
