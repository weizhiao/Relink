use elf_loader::{
    Result,
    arch::NativeArch,
    memory::RegionAccess,
    observer::{
        BeforeLoadEvent, DynamicRelocatedEvent, LinkerObserver, LoadObserver, RelocationObserver,
        SymbolBindingEvent,
    },
    relocation::RelocationArch,
    tls::TlsResolver,
};

const LIBRARY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/example-library/libexample.so"
);

#[derive(Debug, Default)]
struct UserData {
    load_id: u32,
}

#[derive(Default)]
struct Observer {
    next_load_id: u32,
}

impl LoadObserver<UserData> for Observer {
    fn on_before_load(
        &mut self,
        mut event: BeforeLoadEvent<'_, UserData, <NativeArch as RelocationArch>::Layout>,
    ) -> Result<()> {
        self.next_load_id += 1;
        event.user_data_mut().load_id = self.next_load_id;
        println!(
            "loading #{}: {} with {} program headers",
            self.next_load_id,
            event.path(),
            event.phdrs().len()
        );
        Ok(())
    }
}

impl RelocationObserver for Observer {
    fn on_symbol_binding<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
    >(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, NativeArch, R, Tls>,
    ) -> Result<()> {
        println!(
            "binding {} to {:?}",
            event.symbol_name().escape_ascii(),
            event.resolved_addr()
        );
        Ok(())
    }

    fn on_dynamic_relocated<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
    >(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> Result<()> {
        event.lifecycle_mut().set_init_hook(|event| {
            println!(
                "initializing {} with {} functions",
                event.name().escape_ascii(),
                event.lifecycle().func_addrs().count()
            );
            Ok(())
        });
        event.lifecycle_mut().set_fini_hook(|event| {
            println!("finalizing {}", event.name().escape_ascii());
            Ok(())
        });
        Ok(())
    }
}

impl LinkerObserver<UserData> for Observer {}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use elf_loader::{LinkContext, Linker, Loader, input::PathBuf, linker::SearchPathResolver};
    use std::ffi::c_int;

    env_logger::init();
    let mut context = LinkContext::for_process();
    let loaded = Linker::new()
        .with_loader(Loader::new().with_data::<UserData>())
        .with_resolver(SearchPathResolver::new())
        .run()
        .with_observer(Observer::default())
        .load(&mut context, PathBuf::from(LIBRARY))?;

    let module = context.module(loaded.root())?;
    // SAFETY: examples/library/example.c defines int example_value(void).
    let value = unsafe {
        let function = module
            .get::<unsafe extern "C" fn() -> c_int>("example_value")?
            .ok_or("missing example_value")?;
        function()
    };
    println!("after initialization: example_value() = {value}");
    drop(loaded.release(&mut context)?);
    Ok(())
}
