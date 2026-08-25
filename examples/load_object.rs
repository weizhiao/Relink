#[path = "support/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Relocator, Result,
    image::{ModuleHandle, SyntheticModule, SyntheticSymbol},
};

const LOADER: Loader = Loader::new();

fn host_symbols() -> SyntheticModule {
    fn print(s: &str) {
        println!("{}", s);
    }

    SyntheticModule::new(
        "__host",
        [SyntheticSymbol::function("print", print as *const ())],
    )
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let base = Relocator::new()
        .run(LOADER.load_object(fixtures.base_object_str())?)
        .modules([host_symbols()])
        .relocate()?;
    let middle = Relocator::new()
        .run(LOADER.load_dylib(fixtures.middle_str())?)
        .modules([
            ModuleHandle::from(host_symbols()),
            ModuleHandle::from(&base),
        ])
        .relocate()?;
    let leaf = Relocator::new()
        .run(LOADER.load_object(fixtures.leaf_object_str())?)
        .modules([
            ModuleHandle::from(host_symbols()),
            ModuleHandle::from(&base),
            ModuleHandle::from(&middle),
        ])
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
