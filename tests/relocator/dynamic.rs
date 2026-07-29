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
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
fn call_pointer(image: &LoadedCore<()>, name: &str) -> VmAddr {
    let function = unsafe {
        image
            .get::<extern "C" fn() -> *const ()>(name)
            .unwrap_or_else(|| panic!("missing function {name}"))
    };
    VmAddr::from_ptr(function())
}

fn load(name: &str, bytes: &[u8]) -> LoadedCore<()> {
    Relocator::new()
        .run(
            LOADER
                .load_dylib(ElfBinary::new(name, bytes))
                .expect("failed to load relocation fixture"),
        )
        .relocate()
        .expect("failed to relocate fixture")
}

fn host_module() -> SyntheticModule {
    let mut module = SyntheticModule::empty("__host");
    let _ = module.insert(SyntheticSymbol::object(
        SYMBOL,
        &raw const HOST_VALUE as *const (),
        size_of::<i32>(),
    ));
    module
}

#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
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
                    .load_dylib(ElfBinary::new(
                        "binding-consumer.so",
                        &fixtures.binding.consumer,
                    ))
                    .expect("failed to load relocation consumer"),
            )
            .scope([&provider])
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
                    .load_exec(ElfBinary::new(
                        "copy-relocations",
                        &fixtures.copy.executable,
                    ))
                    .expect("failed to load COPY relocation executable"),
            )
            .scope([&provider])
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
                .read_bytes(symbol(&core, name), &mut actual)
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
                    .load_dylib(ElfBinary::new("ifunc.so", &fixtures.ifunc))
                    .expect("failed to load IRELATIVE fixture"),
            )
            .relocate()
            .expect("failed to apply IRELATIVE relocation");

        let call: extern "C" fn() -> i32 = unsafe {
            core::mem::transmute(
                loaded
                    .get::<*const ()>("call_selected")
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
                .load_dylib(ElfBinary::new(
                    "scope-consumer.so",
                    &fixtures.scope.consumer,
                ))
                .expect("failed to load symbol consumer"),
        )
        .scope([
            ModuleHandle::from(host_module()),
            ModuleHandle::from(&provider),
        ])
        .relocate()
        .expect("failed to relocate symbol consumer");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        VmAddr::from_ptr(&raw const HOST_VALUE)
    );
    let scope = relocated.scope();
    assert_eq!(scope.len(), 2);
    assert_eq!(scope[0].name(), "__host");
    assert_eq!(scope[1].name(), provider.name());
}

#[test]
fn loaded_precedes_synthetic() {
    let fixtures = dynamic_fixtures();
    let provider = load("scope-provider.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .load_dylib(ElfBinary::new(
                    "scope-consumer.so",
                    &fixtures.scope.consumer,
                ))
                .expect("failed to load symbol consumer"),
        )
        .scope([
            ModuleHandle::from(&provider),
            ModuleHandle::from(host_module()),
        ])
        .relocate()
        .expect("failed to relocate symbol consumer");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&provider, SYMBOL)
    );
    let scope = relocated.scope();
    assert_eq!(scope.len(), 2);
    assert_eq!(scope[0].name(), provider.name());
    assert_eq!(scope[1].name(), "__host");
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
                .load_dylib(ElfBinary::new(
                    "scope-consumer.so",
                    &fixtures.scope.consumer,
                ))
                .expect("failed to load symbol consumer"),
        )
        .scope(std::slice::from_ref(&first))
        .extend_scope(std::slice::from_ref(&second))
        .relocate()
        .expect("failed to relocate symbol consumer");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&first, SYMBOL)
    );
    let scope = relocated.scope();
    assert_eq!(scope.len(), 2);
    assert_eq!(scope[0].name(), first.name());
    assert_eq!(scope[1].name(), second.name());
}

#[test]
fn scope_interposes_by_default() {
    let fixtures = dynamic_fixtures();
    let provider = load("scope-provider.so", &fixtures.scope.provider);
    let relocated = Relocator::new()
        .run(
            LOADER
                .load_dylib(ElfBinary::new("defining.so", &fixtures.scope.defining))
                .expect("failed to load defining symbol fixture"),
        )
        .scope(std::slice::from_ref(&provider))
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
                .load_dylib(ElfBinary::new("symbolic.so", &fixtures.scope.symbolic))
                .expect("failed to load DF_SYMBOLIC fixture"),
        )
        .scope(std::slice::from_ref(&provider))
        .relocate()
        .expect("failed to relocate DF_SYMBOLIC fixture");

    assert_eq!(
        pointer(&relocated, "external_pointer"),
        symbol(&relocated, SYMBOL)
    );
}
