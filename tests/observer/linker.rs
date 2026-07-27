use elf_loader::{
    LinkContext, Linker,
    arch::NativeArch,
    input::ElfBinary,
    linker::{DependencyRequest, KeyResolver, ResolvedKey, RootRequest},
    memory::RegionAccess,
    observer::{
        DynamicRelocatedEvent, LinkerInitEvent, LinkerObserver, LoadObserver, RelocationObserver,
    },
    runtime::DomainId,
    tls::TlsResolver,
};
use std::sync::{Arc, Mutex};

const NEEDED: &str = "libprovider.so";
const ROOT_NAME: &str = "libdependent.so";
const DEP_NAME: &str = "libprovider.so";

struct Resolver;

impl KeyResolver<&'static str> for Resolver {
    fn load_root<'cfg>(
        &self,
        _req: &RootRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        let fixtures = crate::fixture::fixtures();
        Ok(ResolvedKey::load(
            "root",
            ElfBinary::new(ROOT_NAME, &fixtures.dependent),
        ))
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &DependencyRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        assert_eq!(req.needed(), NEEDED);
        Ok(ResolvedKey::load(
            "dep",
            ElfBinary::new(DEP_NAME, &crate::fixture::fixtures().provider),
        ))
    }
}

struct ReverseInit(Arc<Mutex<Vec<String>>>);

impl LoadObserver for ReverseInit {}

impl LinkerObserver<&'static str, ()> for ReverseInit {
    fn on_init(
        &mut self,
        event: &mut LinkerInitEvent<'_, &'static str, ()>,
    ) -> elf_loader::Result<()> {
        event.modules_mut().reverse();
        Ok(())
    }
}

impl RelocationObserver for ReverseInit {
    fn on_dynamic_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let calls = Arc::clone(&self.0);
        event.lifecycle_mut().set_init_hook(move |event| {
            calls.lock().unwrap().push(event.name().to_string());
            event.lifecycle_mut().clear();
            Ok(())
        });
        Ok(())
    }
}

#[test]
fn reorders_initializers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    Linker::new()
        .resolver(Resolver)
        .run()
        .with_observer(ReverseInit(Arc::clone(&calls)))
        .load(&mut context, "root")
        .expect("load with reordered initialization should succeed");

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[ROOT_NAME.to_string(), DEP_NAME.to_string()]
    );
}
