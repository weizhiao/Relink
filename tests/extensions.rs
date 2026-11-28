#![cfg(all(target_os = "linux", any(feature = "std", feature = "use-syscall")))]

mod fixtures;

use elf_loader::{
    AddressSpaceId, Domain, LinkContext, Linker, Loader, Relocator, Result,
    arch::NativeArch,
    input::ElfBinary,
    linker::{
        SearchPathResolver,
        scan::{DataPass, LinkPass, LinkPassPlan},
    },
    memory::{RegionAccess, VmAddr},
    observer::{RelocationObserver, SymbolBindingEvent},
    tls::TlsResolver,
};
use fixtures::compile;
use std::{ffi::OsStr, fs, os::unix::ffi::OsStrExt};

struct OverrideAdd;

impl RelocationObserver for OverrideAdd {
    fn on_symbol_binding<D: Send + Sync + 'static, R: RegionAccess, T: TlsResolver<NativeArch>>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, NativeArch, R, T>,
    ) -> Result<()> {
        extern "C" fn multiply(a: i32, b: i32) -> i32 {
            a * b
        }
        if event.symbol_name() == b"example_add" {
            event.set_resolved_addr(VmAddr::from_ptr(multiply as *const ()));
        }
        Ok(())
    }
}

#[test]
fn override_constructor_call() -> Result<()> {
    let path = compile(
        "examples/library/example.c",
        "example.so",
        &["-shared", "-fPIC"],
    );
    let bytes = fs::read(OsStr::from_bytes(path.as_bytes())).unwrap();
    let raw = Loader::new()
        .run(Domain::native(AddressSpaceId::PROCESS))
        .load_dylib(ElfBinary::new("embedded.so", &bytes))?;
    let library = Relocator::new()
        .defer_init()
        .run(raw)
        .eager()
        .with_observer(OverrideAdd)
        .relocate()?;

    // The constructor stores example_add(3, 4). The override multiplies them.
    let value = unsafe { library.get::<extern "C" fn() -> i32>("example_value") }?.unwrap();
    assert_eq!(value(), 0);
    library.initialize()?;
    assert_eq!(value(), 12);
    Ok(())
}

#[cfg(feature = "lazy-binding")]
#[test]
fn late_host_symbol() -> Result<()> {
    use elf_loader::{
        image::{SyntheticModule, SyntheticSymbol},
        lazy::NativeLazyBinder,
        linker::GraphModule,
    };

    extern "C" fn host_points() -> i32 {
        100
    }
    let path = compile(
        "tests/fixtures/plugin.c",
        "late.so",
        &["-shared", "-fPIC", "-Wl,-z,lazy"],
    );
    let mut context = LinkContext::for_process();
    let raw = Loader::new()
        .run(context.domain().clone())
        .load_dylib(path)?;
    let plugin = Relocator::new()
        .with_lazy_binder(NativeLazyBinder::new())
        .run(raw)
        .lazy()
        .with_global_scope(context.global_scope())?
        .relocate()?;

    let host = SyntheticModule::new(
        context.domain(),
        "host",
        [SyntheticSymbol::function(
            c"points",
            host_points as *const (),
        )],
    );
    let lease = context.insert(GraphModule::new("host", host))?;
    context.promote_global(lease.id())?;
    let score = unsafe { plugin.get::<extern "C" fn() -> i32>("score") }?.unwrap();
    assert_eq!(score(), 102);
    drop(plugin);
    drop(context.release(lease)?);
    Ok(())
}

struct SetPoints(i32);

impl LinkPass<DataPass> for SetPoints {
    fn run(&mut self, plan: &mut LinkPassPlan<'_, DataPass>) -> Result<()> {
        let section = plan
            .sections()
            .find(|s| s.metadata(plan).name() == b".points")
            .unwrap();
        section
            .data_mut(plan)?
            .copy_from_slice(&self.0.to_ne_bytes());
        Ok(())
    }
}

#[test]
fn configure_before_load() -> Result<()> {
    let path = compile(
        "tests/fixtures/points.c",
        "settings.so",
        &["-shared", "-fPIC", "-Wl,--emit-relocs"],
    );
    let mut context = LinkContext::for_process();
    let loaded = Linker::new()
        .with_resolver(SearchPathResolver::new())
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(SetPoints(75));
            pipeline
        })
        .load_scan_first(&mut context, path)?;
    let module = context.module(loaded.root())?;
    let points = unsafe { module.get::<extern "C" fn() -> i32>("points") }?.unwrap();
    assert_eq!(points(), 75);
    drop(loaded.release(&mut context)?);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[test]
fn reordered_plt() -> Result<()> {
    use elf_loader::{
        linker::scan::{Materialization, ReorderPass},
        relocation::BindingMode,
    };

    struct ReorderPlugin;
    impl LinkPass<ReorderPass> for ReorderPlugin {
        fn run(&mut self, plan: &mut LinkPassPlan<'_, ReorderPass>) -> Result<()> {
            let plugin = plan.root().expect("plugin must support section reordering");
            plugin.set_materialization(plan, Materialization::SectionRegions);
            Ok(())
        }
    }

    compile(
        "tests/fixtures/points.c",
        "libpoints.so",
        &["-shared", "-fPIC"],
    );
    let plugin = compile(
        "tests/fixtures/plugin.c",
        "plugin.so",
        &[
            "-shared",
            "-fPIC",
            "-fplt",
            "-Wl,--emit-relocs,-rpath,$ORIGIN",
            "-L.",
            "-lpoints",
        ],
    );
    for mode in [
        BindingMode::Eager,
        #[cfg(feature = "lazy-binding")]
        BindingMode::Lazy,
    ] {
        let mut context = LinkContext::for_process();
        let mut search = SearchPathResolver::new();
        search.push_runpath().push_rpath();
        let relocator = Relocator::new().with_binding(mode);
        #[cfg(feature = "lazy-binding")]
        let relocator = relocator.with_lazy_binder(elf_loader::lazy::NativeLazyBinder::new());
        let loaded = Linker::new()
            .with_resolver(search)
            .with_relocator(relocator)
            .run()
            .map_pipeline(|mut pipeline| {
                pipeline.push(ReorderPlugin);
                pipeline
            })
            .load_scan_first(&mut context, plugin.clone())?;
        let module = context.module(loaded.root())?;
        let score = unsafe { module.get::<extern "C" fn() -> i32>("score") }?.unwrap();
        // Exercise both the first dispatch and the resolved slot.
        assert_eq!([score(), score()], [42, 42]);
        drop(loaded.release(&mut context)?);
    }
    Ok(())
}
