#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    arch::NativeArch,
    memory::RegionAccess,
    observer::{AfterDynamicLoadEvent, LoadObserver},
    relocation::Relocator,
    tls::TlsResolver,
};

#[allow(dead_code)]
#[derive(Debug)]
struct MyContext {
    load_time: std::time::SystemTime,
    custom_id: u32,
}

impl Default for MyContext {
    fn default() -> Self {
        Self {
            load_time: std::time::SystemTime::now(),
            custom_id: 0,
        }
    }
}

const LOADER: Loader<MyContext> = Loader::new().with_data::<MyContext>();

struct MyObserver;

impl LoadObserver<MyContext> for MyObserver {
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        mut event: AfterDynamicLoadEvent<'_, MyContext, NativeArch, R, Tls>,
    ) -> Result<()> {
        println!("Initializing user data for: {}", event.raw().name());
        if let Some(context) = event.raw_mut().user_data_mut() {
            context.load_time = std::time::SystemTime::now();
            context.custom_id = 42;
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let lib = Relocator::new()
        .run(
            LOADER
                .run()
                .with_observer(MyObserver)
                .load_dylib(fixtures.liba_str())?,
        )
        .relocate()?;

    let context = lib.user_data();
    println!("Loaded {:?} with context: {:?}", lib.name(), context);

    Ok(())
}
