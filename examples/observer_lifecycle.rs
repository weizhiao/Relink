#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Relocator, Result,
    arch::NativeArch,
    memory::RegionAccess,
    observer::{DynamicRelocatedEvent, RelocationObserver},
    tls::TlsResolver,
};

const LOADER: Loader = Loader::new();

struct LifecycleLogger;

impl RelocationObserver for LifecycleLogger {
    fn on_dynamic_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> Result<()> {
        event.set_init_hook(|event| {
            println!("Init hook called for {}!", event.name());
            let mut count = 0;
            for addr in event.lifecycle().func_addrs() {
                count += 1;
                println!("Init function at {addr}");
            }
            if count != 0 {
                println!("Init lifecycle has {count} functions");
            }

            Ok(())
        });
        Ok(())
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let _lib = Relocator::new()
        .run(LOADER.load_dylib(fixtures.liba_str())?)
        .observer(LifecycleLogger)
        .relocate()?;
    println!("Library loaded and relocated.");

    Ok(())
}
