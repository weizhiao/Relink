use elf_loader::arch::NativeArch;
use elf_loader::{AddressSpaceId, Domain};
use elf_loader::{
    Loader,
    image::{LoadedCore, Module, ModuleHandle, SyntheticModule, SyntheticSymbol},
    input::ElfBinary,
    memory::{ImageMemoryExt, VmAddr},
    relocation::Relocator,
};

use crate::fixtures::dynamic as dynamic_fixtures;

const LOADER: Loader = Loader::new();
const SYMBOL: &str = "external_value";

static mut HOST_VALUE: i32 = 100;

fn symbol(image: &LoadedCore<()>, name: &str) -> VmAddr {
    unsafe {
        VmAddr::from_ptr(
            image
                .get::<u8>(name)
                .expect("symbol lookup failed")
                .unwrap_or_else(|| panic!("missing symbol {name}"))
                .into_raw(),
        )
    }
}

fn pointer(image: &LoadedCore<()>, name: &str) -> VmAddr {
    VmAddr::new(unsafe {
        image
            .segments()
            .read_value::<usize>(symbol(image, name))
            .unwrap_or_else(|_| panic!("failed to read pointer symbol {name}"))
    })
}

#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "std")
))]
fn call_pointer(image: &LoadedCore<()>, name: &str) -> VmAddr {
    let function = unsafe {
        image
            .get::<extern "C" fn() -> *const ()>(name)
            .expect("symbol lookup failed")
            .unwrap_or_else(|| panic!("missing function {name}"))
    };
    VmAddr::from_ptr(function())
}

fn load(name: &str, bytes: &[u8]) -> LoadedCore<()> {
    Relocator::new()
        .run(
            LOADER
                .run(elf_loader::Domain::native(
                    elf_loader::AddressSpaceId::PROCESS,
                ))
                .load_dylib(ElfBinary::new(name, bytes))
                .expect("failed to load relocation fixture"),
        )
        .relocate()
        .expect("failed to relocate fixture")
}

fn host_module() -> SyntheticModule {
    let mut module = SyntheticModule::empty(
        &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
        "__host",
    );
    let _ = module.insert(SyntheticSymbol::object(
        std::ffi::CString::new(SYMBOL).unwrap(),
        &raw const HOST_VALUE as *const (),
        size_of::<i32>(),
    ));
    module
}

#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "std")
))]
mod native {
    use super::*;
    #[cfg(not(target_arch = "loongarch64"))]
    use elf_loader::memory::ImageMemory;

    #[cfg(not(target_arch = "loongarch64"))]
    const COPY_A: &str = "copy_a";
    #[cfg(not(target_arch = "loongarch64"))]
    const COPY_B: &str = "copy_b";
    #[test]
    fn eager_binding() {
        let fixtures = dynamic_fixtures();
        let provider = load("binding-provider.so", &fixtures.binding.provider);
        let loaded = Relocator::new()
            .run(
                LOADER
                    .run(elf_loader::Domain::native(
                        elf_loader::AddressSpaceId::PROCESS,
                    ))
                    .load_dylib(ElfBinary::new(
                        "binding-consumer.so",
                        &fixtures.binding.consumer,
                    ))
                    .expect("failed to load relocation consumer"),
            )
            .with_modules([&provider])
            .expect("incompatible relocation modules")
            .relocate()
            .expect("failed to relocate consumer");

        assert_eq!(
            pointer(&loaded, "external_pointer"),
            symbol(&provider, SYMBOL)
        );

        let call: extern "C" fn(i32) -> i32 = unsafe {
            core::mem::transmute(
                loaded
                    .get::<*const ()>("call_external")
                    .expect("symbol lookup failed")
                    .expect("missing call_external")
                    .into_raw(),
            )
        };
        assert_eq!(call(5), 22);
    }

    #[test]
    // LoongArch GCC keeps external data indirect and does not emit R_LARCH_COPY here.
    #[cfg(not(target_arch = "loongarch64"))]
    fn copy_symbols_stay_distinct() {
        let fixtures = dynamic_fixtures();
        let provider = load("copy-provider.so", &fixtures.copy.provider);
        let loaded = Relocator::new()
            .run(
                LOADER
                    .run(elf_loader::Domain::native(
                        elf_loader::AddressSpaceId::PROCESS,
                    ))
                    .load_exec(ElfBinary::new(
                        "copy-relocations",
                        &fixtures.copy.executable,
                    ))
                    .expect("failed to load COPY relocation executable"),
            )
            .with_modules([&provider])
            .expect("incompatible relocation modules")
            .relocate()
            .expect("failed to relocate COPY executable");
        let core = loaded
            .core_ref()
            .expect("COPY fixture should be a dynamic executable");

        for (name, expected) in [
            (COPY_A, &[0x10, 0x20, 0x30, 0x40][..]),
            (COPY_B, &[0x55, 0x66, 0x77, 0x88, 0x99][..]),
        ] {
            let mut actual = vec![0; expected.len()];
            core.segments()
                .read_bytes(symbol(core, name), &mut actual)
                .unwrap_or_else(|_| panic!("failed to read symbol {name}"));
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn relative_relocations() {
        let fixtures = dynamic_fixtures();
        let loaded = load("relative.so", &fixtures.relative);

        assert_eq!(
            pointer(&loaded, "relative_pointer"),
            call_pointer(&loaded, "local_address")
        );

        let read: extern "C" fn() -> i32 = unsafe {
            core::mem::transmute(
                loaded
                    .get::<*const ()>("read_relative")
                    .expect("symbol lookup failed")
                    .expect("missing read_relative")
                    .into_raw(),
            )
        };
        assert_eq!(read(), 23);
    }

    #[test]
    fn irelative_relocations() {
        let fixtures = dynamic_fixtures();
        let loaded = Relocator::new()
            .run(
                LOADER
                    .run(elf_loader::Domain::native(
                        elf_loader::AddressSpaceId::PROCESS,
                    ))
                    .load_dylib(ElfBinary::new("ifunc.so", &fixtures.ifunc))
                    .expect("failed to load IRELATIVE fixture"),
            )
            .relocate()
            .expect("failed to apply IRELATIVE relocation");

        let call: extern "C" fn() -> i32 = unsafe {
            core::mem::transmute(
                loaded
                    .get::<*const ()>("call_selected")
                    .expect("symbol lookup failed")
                    .expect("missing call_selected")
                    .into_raw(),
            )
        };
        assert_eq!(call(), 73);
    }
}

#[test]
fn synthetic_precedes_loaded() {
    let fixtures = dynamic_fixtures();
    let provider = load("scope-provider.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .run(elf_loader::Domain::native(
                    elf_loader::AddressSpaceId::PROCESS,
                ))
                .load_dylib(ElfBinary::new(
                    "scope-consumer.so",
                    &fixtures.scope.consumer,
                ))
                .expect("failed to load symbol consumer"),
        )
        .with_modules([
            ModuleHandle::from(host_module()),
            ModuleHandle::from(&provider),
        ])
        .expect("incompatible relocation modules")
        .relocate()
        .expect("failed to relocate symbol consumer");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        VmAddr::from_ptr(&raw const HOST_VALUE)
    );
    let scope = relocated.scope();
    assert_eq!(scope.len(), 2);
    let mut modules = scope.iter();
    assert_eq!(modules.next().unwrap().name(), b"__host");
    assert_eq!(modules.next().unwrap().name(), provider.name());
}

#[test]
fn loaded_precedes_synthetic() {
    let fixtures = dynamic_fixtures();
    let provider = load("scope-provider.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .run(elf_loader::Domain::native(
                    elf_loader::AddressSpaceId::PROCESS,
                ))
                .load_dylib(ElfBinary::new(
                    "scope-consumer.so",
                    &fixtures.scope.consumer,
                ))
                .expect("failed to load symbol consumer"),
        )
        .with_modules([
            ModuleHandle::from(&provider),
            ModuleHandle::from(host_module()),
        ])
        .expect("incompatible relocation modules")
        .relocate()
        .expect("failed to relocate symbol consumer");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&provider, SYMBOL)
    );
    let scope = relocated.scope();
    assert_eq!(scope.len(), 2);
    let mut modules = scope.iter();
    assert_eq!(modules.next().unwrap().name(), provider.name());
    assert_eq!(modules.next().unwrap().name(), b"__host");
}

#[test]
fn weak_undef_is_zero() {
    let fixtures = dynamic_fixtures();
    let loaded = load("weak.so", &fixtures.weak);

    assert_eq!(pointer(&loaded, "weak_pointer"), VmAddr::null());
}

#[test]
fn extend_preserves_precedence() {
    let fixtures = dynamic_fixtures();
    let first = load("first.so", &fixtures.scope.provider);
    let second = load("second.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .run(elf_loader::Domain::native(
                    elf_loader::AddressSpaceId::PROCESS,
                ))
                .load_dylib(ElfBinary::new(
                    "scope-consumer.so",
                    &fixtures.scope.consumer,
                ))
                .expect("failed to load symbol consumer"),
        )
        .with_modules([&first, &second])
        .expect("incompatible relocation modules")
        .relocate()
        .expect("failed to relocate symbol consumer");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&first, SYMBOL)
    );
    let scope = relocated.scope();
    assert_eq!(scope.len(), 2);
    let mut modules = scope.iter();
    assert_eq!(modules.next().unwrap().name(), first.name());
    assert_eq!(modules.next().unwrap().name(), second.name());
}

#[test]
fn scope_interposes_by_default() {
    let fixtures = dynamic_fixtures();
    let provider = load("scope-provider.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .run(elf_loader::Domain::native(
                    elf_loader::AddressSpaceId::PROCESS,
                ))
                .load_dylib(ElfBinary::new("defining.so", &fixtures.scope.defining))
                .expect("failed to load defining symbol fixture"),
        )
        .with_modules(std::slice::from_ref(&provider))
        .expect("incompatible relocation modules")
        .relocate()
        .expect("failed to relocate defining symbol fixture");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&provider, SYMBOL)
    );
}

#[test]
fn symbolic_prefers_self() {
    let fixtures = dynamic_fixtures();
    let provider = load("scope-provider.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .run(elf_loader::Domain::native(
                    elf_loader::AddressSpaceId::PROCESS,
                ))
                .load_dylib(ElfBinary::new("symbolic.so", &fixtures.scope.symbolic))
                .expect("failed to load DF_SYMBOLIC fixture"),
        )
        .with_modules(std::slice::from_ref(&provider))
        .expect("incompatible relocation modules")
        .relocate()
        .expect("failed to relocate DF_SYMBOLIC fixture");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&relocated, SYMBOL)
    );
}

#[test]
fn images_without_tls_retain_their_domain_at_admission() {
    use elf_loader::{
        Error, LinkContext, Linker, Result,
        arch::NativeArch,
        error::TlsError,
        image::{LocalScope, ModuleScope},
        linker::SearchPathResolver,
        tls::{TlsInfo, TlsModuleId, TlsRegistration, TlsRequest, TlsResolver, TlsTemplate},
    };
    #[derive(Clone)]
    struct Resolver(usize);
    impl TlsResolver<NativeArch> for Resolver {
        fn register(&self, _: TlsInfo, _: TlsRequest) -> Result<TlsRegistration> {
            Err(TlsError::ResolverUnsupported.into())
        }
        fn publish(&self, _: TlsTemplate, _: TlsModuleId) -> Result<()> {
            Err(TlsError::ResolverUnsupported.into())
        }
        fn bind_tls_get_addr(&self) -> Result<VmAddr> {
            Ok(VmAddr::new(self.0))
        }
    }
    let fixtures = dynamic_fixtures();
    let load = || {
        LOADER
            .run(
                Domain::native(AddressSpaceId::PROCESS)
                    .with_tls(Resolver(0x1000))
                    .unwrap(),
            )
            .load_dylib(ElfBinary::new("provider.so", &fixtures.binding.provider))
            .unwrap()
    };
    let raw = load();
    assert!(raw.tls().is_none());
    let foreign = Resolver(0x2000);
    let mut modules = ModuleScope::new(
        Domain::native(AddressSpaceId::PROCESS)
            .with_tls(foreign.clone())
            .unwrap()
            .id(),
    );
    assert!(matches!(
        modules.push(ModuleHandle::from(raw.clone())),
        Err(Error::DomainMismatch(_))
    ));
    let scope = LocalScope::from_group(modules);
    let relocator = Relocator::new();
    assert!(matches!(
        relocator.run(load()).with_local_scope(scope),
        Err(Error::DomainMismatch(_))
    ));

    let mut context = LinkContext::<(), NativeArch, Resolver>::new(
        Domain::native(AddressSpaceId::PROCESS)
            .with_tls(foreign)
            .unwrap(),
    );
    assert!(matches!(
        relocator
            .run(load())
            .with_global_scope(context.global_scope()),
        Err(Error::DomainMismatch(_))
    ));
    let linker = Linker::new().with_resolver(SearchPathResolver::new());
    assert!(matches!(
        linker
            .run()
            .prepare_mapped(&mut context, "provider.so".into(), raw.into()),
        Err(Error::DomainMismatch(_))
    ));
    assert!(context.is_empty());
}
