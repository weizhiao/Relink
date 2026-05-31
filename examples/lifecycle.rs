#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    arch::NativeArch,
    observer::{LifecycleEvent, LifecyclePhase, RelocationObserver},
    os::RegionAccess,
};

struct LifecycleLogger;

impl RelocationObserver for LifecycleLogger {
    fn on_init<R: RegionAccess>(
        &mut self,
        event: &mut LifecycleEvent<'_, NativeArch, R>,
    ) -> Result<()> {
        let label = match event.phase() {
            LifecyclePhase::Init => "Init",
            LifecyclePhase::Fini => "Fini",
        };

        println!("{label} lifecycle hook called!");
        let mut count = 0;
        for addr in event.lifecycle().func_addrs() {
            count += 1;
            println!("{label} function at {addr}");
        }
        if count != 0 {
            println!("{label} lifecycle has {count} functions");
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
