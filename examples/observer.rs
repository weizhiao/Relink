#[path = "support/mod.rs"]
mod fixture_support;

use elf_loader::{
    LinkContext, Linker, Loader, Result,
    arch::NativeArch,
    input::PathBuf,
    memory::{RegionAccess, VmAddr},
    observer::{
        BeforeLoadEvent, DynamicRelocatedEvent, LinkerObserver, LoadObserver, RelocationObserver,
        SymbolBindingEvent,
    },
    relocation::RelocationArch,
    runtime::DomainId,
    tls::TlsResolver,
};

#[derive(Debug, Default)]
struct UserData {
    load_id: u32,
}

const LOADER: Loader<UserData> = Loader::new().with_data();

struct Observer;

fn host_print(message: &str) {
    println!("host print: {message}");
}

impl LoadObserver<UserData> for Observer {
    fn on_before_load(
        &mut self,
        mut event: BeforeLoadEvent<'_, UserData, <NativeArch as RelocationArch>::Layout>,
    ) -> Result<()> {
        println!(
            "loading {} with {} program headers",
            event.path(),
            event.phdrs().len()
        );
        event.user_data_mut().load_id = 42;
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
        if event.symbol_name() == "print" {
            event.set_resolved_addr(VmAddr::from_ptr(host_print as *const ()));
        }
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
                event.name(),
                event.lifecycle().func_addrs().count()
            );
            Ok(())
        });
        Ok(())
    }
}

impl LinkerObserver<UserData> for Observer {}

fn main() -> Result<()> {
    let fixtures = fixture_support::ensure_all();
    let linker = Linker::<PathBuf>::new()
        .loader(LOADER)
        .resolver(fixture_support::search_path_resolver());
    let mut context: LinkContext<PathBuf> = LinkContext::new(DomainId::PROCESS);
    let middle = linker
        .run()
        .with_observer(Observer)
        .load(&mut context, PathBuf::from(fixtures.middle_str()))?;
    let module = context.module(middle.root())?;

    let middle_value = unsafe {
        module
            .get::<extern "C" fn() -> i32>("middle_value")
            .expect("missing middle_value")
    };
    println!("middle_value() = {} from {}", middle_value(), module.name());
    Ok(())
}
