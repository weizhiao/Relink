#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    image::{ModuleHandle, SyntheticModule, SyntheticSymbol},
    relocation::Relocator,
};

const LOADER: Loader = Loader::new();
const RELOCATOR: Relocator = Relocator::new();

fn host_symbols() -> ModuleHandle {
    fn print(s: &str) {
        println!("{}", s);
    }

    SyntheticModule::new(
        "__host",
        [SyntheticSymbol::function("print", print as *const ())],
    )
    .into()
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let host = host_symbols();
    let liba = RELOCATOR
        .run(LOADER.load_dylib(fixtures.liba_str())?)
        .scope([host.clone()])
        .relocate()?;
    let libb = RELOCATOR
        .run(LOADER.load_dylib(fixtures.libb_str())?)
        .scope([host.clone()])
        .extend_scope([&liba])
        .relocate()?;
    let libc = RELOCATOR
        .run(LOADER.load_dylib(fixtures.libc_str())?)
        .scope([host])
        .extend_scope([&liba, &libb])
        .relocate()?;
    let f = unsafe { liba.get::<fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { libb.get::<fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { libc.get::<fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
    Ok(())
}
