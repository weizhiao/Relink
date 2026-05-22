#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, Result, loader::LifecycleContext};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new()
        .with_init(|ctx: &LifecycleContext<'_>| {
            println!("Initialization hook called!");
            let mut init_count = 0;
            for ptr in ctx.func_addrs() {
                init_count += 1;
                println!("Init function at {:p}", ptr.as_ptr());
            }
            if init_count != 0 {
                println!("Init lifecycle has {init_count} functions");
            }
        })
        .with_fini(|ctx: &LifecycleContext<'_>| {
            println!("Finalization hook called!");
            let mut fini_count = 0;
            for ptr in ctx.func_addrs() {
                fini_count += 1;
                println!("Fini function at {:p}", ptr.as_ptr());
            }
            if fini_count != 0 {
                println!("Fini lifecycle has {fini_count} functions");
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
