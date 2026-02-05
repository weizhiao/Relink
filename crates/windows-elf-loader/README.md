# windows-elf-loader
Be capable of loading the elf dynamic library on Windows. This crate is implemented based on [rust-elfloader](https://github.com/weizhiao/rust-elfloader). The dynamic library used in example is also derived from [rust-elfloader](https://github.com/weizhiao/rust-elfloader).

# Example
```
$ cargo run -r --example load 
```
```rust
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
```

# Note
Here are the translated notes:
* You need to manually handle the ELF dynamic library dependencies.
* Do not directly use syscalls within ELF dynamic libraries.
* ABI conversion is required at the calling boundary between ELF dynamic libraries and Windows programs, as demonstrated in the example.