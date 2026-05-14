use elf_loader::image::{SyntheticModule, SyntheticSymbol};
use std::ffi::CStr;
use windows_elf_loader::WinElfLoader;

fn main() {
    extern "sysv64" fn print(s: *const i8) {
        let s = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        println!("{}", s);
    }
    // Symbols required by dynamic library liba.so
    let host = SyntheticModule::new(
        "__host",
        [SyntheticSymbol::function("print", print as *const ())],
    );
    let mut loader: WinElfLoader = WinElfLoader::new();
    // Load and relocate dynamic library liba.so
    let liba = loader
        .load_file(r".\crates\windows-elf-loader\example_dylib\liba.so")
        .unwrap()
        .relocator()
        .scope([host])
        .relocate()
        .unwrap();
    // Call function a in liba.so
    let f = unsafe { liba.get::<extern "sysv64" fn() -> i32>("a").unwrap() };
    println!("{}", f());
}
