#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    image::{ModuleHandle, SyntheticModule, SyntheticSymbol},
};

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
    let mut loader = Loader::new();
    let a = loader
        .load_object(fixtures.a_object_str())?
        .relocator()
        .scope([host_symbols()])
        .relocate()?;
    let b = loader
        .load_dylib(fixtures.libb_str())?
        .relocator()
        .scope([ModuleHandle::from(host_symbols()), ModuleHandle::from(&a)])
        .relocate()?;
    let c = loader
        .load_object(fixtures.c_object_str())?
        .relocator()
        .scope([
            ModuleHandle::from(host_symbols()),
            ModuleHandle::from(&a),
            ModuleHandle::from(&b),
        ])
        .relocate()?;
    let f = unsafe { a.get::<extern "C" fn() -> i32>("a").unwrap() };
    assert!(f() == 1);
    let f = unsafe { b.get::<extern "C" fn() -> i32>("b").unwrap() };
    assert!(f() == 2);
    let f = unsafe { c.get::<extern "C" fn() -> i32>("c").unwrap() };
    assert!(f() == 3);
    Ok(())
}
