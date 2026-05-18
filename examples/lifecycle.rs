#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, Result, loader::LifecycleContext};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new()
        .with_init(|ctx: &LifecycleContext<'_>| {
            println!("Initialization hook called!");
            if let Some(addr) = ctx.func_addr() {
                println!("Single init function at 0x{:x}", addr.get());
            }
            let init_array_len = ctx.func_array_addrs().count();
            if init_array_len != 0 {
                println!("Init array has {init_array_len} functions");
            }
        })
        .with_fini(|ctx: &LifecycleContext<'_>| {
            println!("Finalization hook called!");
            if let Some(addr) = ctx.func_addr() {
                println!("Single fini function at 0x{:x}", addr.get());
            }
            let fini_array_len = ctx.func_array_addrs().count();
            if fini_array_len != 0 {
                println!("Fini array has {fini_array_len} functions");
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
