#![cfg(all(target_os = "linux", any(feature = "std", feature = "use-syscall")))]

mod fixtures;

use elf_loader::{
    AddressSpaceId, Domain, Loader, Relocator, Result,
    arch::NativeArch,
    input::ElfBinary,
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

#[test]
fn retry_failed_load_rollback() -> Result<()> {
    use elf_loader::{
        Error, LinkContext, Linker,
        error::CustomError,
        linker::SearchPathResolver,
        observer::{DynamicRelocatedEvent, LinkerObserver, LoadObserver},
    };

    struct RejectInit;
    impl LoadObserver for RejectInit {}
    impl LinkerObserver for RejectInit {}
    impl RelocationObserver for RejectInit {
        fn on_dynamic_relocated<
            D: Send + Sync + 'static,
            R: RegionAccess,
            T: TlsResolver<NativeArch>,
        >(
            &mut self,
            event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, T>,
        ) -> Result<()> {
            event
                .lifecycle_mut()
                .set_init_hook(|_| Err(CustomError::message("init rejected").into()));
            Ok(())
        }
    }

    let path = compile(
        "tests/fixtures/points.c",
        "rollback.so",
        &["-shared", "-fPIC"],
    );
    let linker = Linker::new().with_resolver(SearchPathResolver::new());
    let mut run = linker.run().with_observer(RejectInit);
    let mut owner = LinkContext::for_process();
    let mut other = LinkContext::for_process();
    let prepared = run.prepare_load(&mut owner, path)?;
    let published = run.relocate(prepared)?.publish(&mut owner)?;
    let published = published.rollback(&mut other).unwrap_err().acquisition;
    let failed = published.initialize().unwrap_err();
    let failed = failed.rollback(&mut other).unwrap_err().acquisition;
    let error = failed.rollback(&mut owner)?;
    assert!(matches!(error, Error::Custom(CustomError::Message(msg)) if msg == "init rejected"));
    assert!(owner.is_empty());
    Ok(())
}

#[cfg(feature = "lazy-binding")]
#[test]
fn late_host_symbol() -> Result<()> {
    use elf_loader::{
        LinkContext,
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
