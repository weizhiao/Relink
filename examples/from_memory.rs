#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::Loader;
use std::{fs::File, io::Read};

fn main() {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();
    let fixtures = fixture_support::ensure_all();
    let mut file = File::open(&fixtures.liba).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    let liba = Loader::new().load_dylib(&bytes).unwrap();
    let a = liba.relocator().relocate().unwrap();
    let f = unsafe { a.get::<fn() -> i32>("a").unwrap() };
    println!("{}", f());
}
