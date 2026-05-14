#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, Result, elf::Lifecycle};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new()
        .with_init(|ctx: &Lifecycle<'_>| {
            println!("Initialization hook called!");
            if let Some(f) = ctx.func() {
                println!("Single init function at {:p}", f as *const ());
            }
            if let Some(arr) = ctx.func_array() {
                println!("Init array has {} functions", arr.len());
            }
        })
        .with_fini(|ctx: &Lifecycle<'_>| {
            println!("Finalization hook called!");
            if let Some(f) = ctx.func() {
                println!("Single fini function at {:p}", f as *const ());
            }
            if let Some(arr) = ctx.func_array() {
                println!("Fini array has {} functions", arr.len());
            }
        });

    let fixtures = fixture_support::ensure_all();
    let _lib = loader
        .load_dylib(fixtures.liba_str())?
        .relocator()
        .relocate()?;
    println!("Library loaded and relocated.");

    Ok(())
}
