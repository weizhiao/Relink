#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    arch::NativeArch,
    memory::RegionAccess,
    observer::{InitEvent, RelocationObserver},
};

struct LifecycleLogger;

impl RelocationObserver for LifecycleLogger {
    fn on_init<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut InitEvent<'_, D, NativeArch, R, H>,
    ) -> Result<()> {
        println!("Init hook called!");
        let mut count = 0;
        for addr in event.lifecycle().func_addrs() {
            count += 1;
            println!("Init function at {addr}");
        }
        if count != 0 {
            println!("Init lifecycle has {count} functions");
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new();

    let fixtures = fixture_support::ensure_all();
    let _lib = loader
        .load_dylib(fixtures.liba_str())?
        .relocator()
        .observer(LifecycleLogger)
        .relocate()?;
    println!("Library loaded and relocated.");

    Ok(())
}
