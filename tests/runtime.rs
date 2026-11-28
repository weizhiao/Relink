#![cfg(all(target_os = "linux", any(feature = "std", feature = "use-syscall")))]

mod fixtures;

use elf_loader::{LinkContext, Linker, Result, linker::SearchPathResolver, memory::VmAddr};
use fixtures::compile;

#[test]
fn load_plugin() -> Result<()> {
    let points = compile(
        "tests/fixtures/points.c",
        "libpoints.so",
        &["-fPIC", "-shared"],
    );
    let plugin = compile(
        "tests/fixtures/plugin.c",
        "plugin.so",
        &["-fPIC", "-shared", "-L.", "-lpoints", "-Wl,-rpath,$ORIGIN"],
    );
    let mut search = SearchPathResolver::new();
    search.push_rpath().push_runpath();
    let linker = Linker::new().with_resolver(search);
    let mut context = LinkContext::for_process();
    let plugin = linker.run().load(&mut context, plugin)?;
    let module = context.module(plugin.root())?;
    let score = unsafe { module.get::<extern "C" fn() -> i32>("score") }?.unwrap();
    let caller = context
        .address_at(VmAddr::from_ptr(score.into_raw()))
        .unwrap();
    let mut target = LinkContext::for_process();
    let imported = target.import(&context, plugin.root())?;
    assert!(module.ptr_eq(target.module(imported.id())?));

    // Holding the dependency open lets us inspect it after unloading the plugin.
    let points = linker.run().load(&mut context, points)?;
    assert_eq!(context.module_loader(points.root())?, Some(caller.owner));
    let plugin = plugin.release(&mut target).unwrap_err().acquisition;
    drop(plugin.release(&mut context)?);
    assert_eq!(context.module_loader(points.root())?, None);
    drop(points.release(&mut context)?);
    assert!(context.is_empty());

    let dependency = target.direct_deps(imported.id())?.next().unwrap();
    assert_eq!(target.module_loader(dependency)?, Some(imported.id()));
    let module = target.module(imported.id())?;
    let score = unsafe { module.get::<extern "C" fn() -> i32>("score") }?.unwrap();
    assert_eq!(score(), 42);
    let imported = context.pin(imported).unwrap_err().acquisition;
    drop(target.release(imported)?);
    assert!(target.is_empty());
    Ok(())
}

#[test]
fn interpreter_path() -> Result<()> {
    use elf_loader::{AddressSpaceId, Domain, Loader};

    let path = compile(
        "tests/fixtures/interpreter.c",
        "interpreter.so",
        &["-fPIC", "-shared"],
    );
    let loader = Loader::new();
    let mut run = loader.run(Domain::native(AddressSpaceId::PROCESS));
    let scanned = run.scan(path.clone())?;
    let mapped = run.load(path)?;
    assert_eq!(scanned.interp(), Some(b"/runtime/\xff".as_slice()));
    assert_eq!(mapped.interp(), scanned.interp());
    let dynamic = run.load_scanned_dynamic(scanned.into_dynamic().unwrap())?;
    assert_eq!(dynamic.interp(), mapped.interp());
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn thread_local_counter() -> Result<()> {
    use elf_loader::{AddressSpaceId, Domain, Loader, Relocator, tls::DefaultTlsResolver};

    let path = compile(
        "benches/fixtures/tls.c",
        "counter.so",
        &["-fPIC", "-shared"],
    );
    let domain = Domain::native(AddressSpaceId::PROCESS).with_tls(DefaultTlsResolver::new())?;
    let raw = Loader::new().run(domain).load_dylib(path)?;
    let counter = Relocator::new().run(raw).relocate()?;
    let increment = unsafe { counter.get::<extern "C" fn() -> u64>("tls_increment") }?.unwrap();

    assert_eq!(increment(), 8);
    std::thread::scope(|s| {
        s.spawn(|| assert_eq!(increment(), 8));
    });
    assert_eq!(increment(), 9);
    Ok(())
}

#[cfg(all(
    feature = "object",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
#[test]
fn link_objects() -> Result<()> {
    use elf_loader::{AddressSpaceId, Domain, Loader, Relocator};

    let domain = Domain::native(AddressSpaceId::PROCESS);
    let loader = Loader::new();
    let mut run = loader.run(domain);
    let points = compile("tests/fixtures/points.c", "points.o", &["-c"]);
    let points = Relocator::new().run(run.load_object(points)?).relocate()?;
    let plugin = compile("tests/fixtures/plugin.c", "plugin.o", &["-c"]);
    let plugin = Relocator::new()
        .run(run.load_object(plugin)?)
        .with_modules([&points])?
        .relocate()?;

    let score = unsafe { plugin.get::<extern "C" fn() -> i32>("score") }?.unwrap();
    assert_eq!(score(), 42);
    Ok(())
}
