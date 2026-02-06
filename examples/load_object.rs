use core::str;
use elf_loader::{Loader, Result};
use std::collections::HashMap;

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    fn print(s: &str) {
        println!("{}", s);
    }

    let mut map = HashMap::new();
    map.insert("print", print as *const () as usize);
    let pre_find =
        |name: &str| -> Option<*const ()> { map.get(name).copied().map(|p| p as *const ()) };
    let mut loader = Loader::new();
    let a = loader
        .load_object("target/a.o")?
        .relocator()
        .pre_find(&pre_find)
        .relocate()?;
    let b = loader
        .load_dylib("target/libb.so")?
        .relocator()
        .pre_find(&pre_find)
        .scope([&a])
        .relocate()?;
    let c = loader
        .load_object("target/c.o")?
        .relocator()
        .pre_find(&pre_find)
        .scope([&a])
        .add_scope([&b])
        .relocate()?;
    let f = unsafe { a.get::<extern "C" fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { b.get::<extern "C" fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { c.get::<extern "C" fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
    Ok(())
}
