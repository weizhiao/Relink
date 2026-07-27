#[path = "support/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Relocator, Result,
    image::{ModuleHandle, SyntheticModule, SyntheticSymbol},
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
    let base = RELOCATOR
        .run(LOADER.load_dylib(fixtures.base_str())?)
        .scope([host.clone()])
        .relocate()?;
    let middle = RELOCATOR
        .run(LOADER.load_dylib(fixtures.middle_str())?)
        .scope([host.clone()])
        .extend_scope([&base])
        .relocate()?;
    let leaf = RELOCATOR
        .run(LOADER.load_dylib(fixtures.leaf_str())?)
        .scope([host])
        .extend_scope([&base, &middle])
        .relocate()?;
    let f = unsafe { base.get::<extern "C" fn() -> i32>("base_value").unwrap() };
    assert!(f() == 1);
    let f = unsafe {
        middle
            .get::<extern "C" fn() -> i32>("middle_value")
            .unwrap()
    };
    assert!(f() == 2);
    let f = unsafe { leaf.get::<extern "C" fn() -> i32>("leaf_value").unwrap() };
    assert!(f() == 3);
    Ok(())
}
