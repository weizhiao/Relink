#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, relocation::Relocator};
use std::{fs::File, io::Read};

const LOADER: Loader = Loader::new();

fn main() {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();
    let fixtures = fixture_support::ensure_all();
    let mut file = File::open(&fixtures.liba).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    let a = Relocator::new()
        .run(LOADER.load_dylib(&bytes).unwrap())
        .relocate()
        .unwrap();
    let f = unsafe { a.get::<fn() -> i32>("a").unwrap() };
    println!("{}", f());
}
