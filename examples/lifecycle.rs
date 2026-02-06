use elf_loader::{Loader, Result};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new()
        .with_init(|ctx: &elf_loader::loader::LifecycleContext| {
            println!("Initialization hook called!");
            if let Some(f) = ctx.func() {
                println!("Single init function at {:p}", f as *const ());
            }
            if let Some(arr) = ctx.func_array() {
                println!("Init array has {} functions", arr.len());
            }
        })
        .with_fini(|ctx: &elf_loader::loader::LifecycleContext| {
            println!("Finalization hook called!");
            if let Some(f) = ctx.func() {
                println!("Single fini function at {:p}", f as *const ());
            }
            if let Some(arr) = ctx.func_array() {
                println!("Fini array has {} functions", arr.len());
            }
        });

    // Load the library. (Make sure liba.so exists in target/ folder)
    let _lib = loader
        .load_dylib("target/liba.so")?
        .relocator()
        .relocate()?;
    println!("Library loaded and relocated.");

    Ok(())
}
