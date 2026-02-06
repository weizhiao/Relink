use elf_loader::{Loader, Result};
use std::collections::HashMap;

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    fn print(s: &str) {
        println!("{}", s);
    }

    let mut map = HashMap::new();
    map.insert("print", print as _);
    let pre_find = |name: &str| -> Option<*const ()> { map.get(name).copied() };
    let mut loader = Loader::new();
    let liba = loader
        .load_dylib("target/liba.so")?
        .relocator()
        .pre_find(&pre_find)
        .relocate()?;
    let libb = loader
        .load_dylib("target/libb.so")?
        .relocator()
        .pre_find(&pre_find)
        .scope([&liba])
        .relocate()?;
    let libc = loader
        .load_dylib("target/libc.so")?
        .relocator()
        .pre_find(&pre_find)
        .scope([&liba, &libb])
        .relocate()?;
    let f = unsafe { liba.get::<fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { libb.get::<fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { libc.get::<fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
    Ok(())
}
