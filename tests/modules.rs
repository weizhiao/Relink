use elf_loader::{
    AddressSpaceId, Domain, Loader, Relocator, Result,
    arch::x86::X86Arch,
    elf::write::{DsoBuilder, DsoExport},
    input::ElfBinary,
    os::AllocMmap,
    runtime::NativeCodeExecutor,
};

#[cfg(all(target_os = "linux", any(feature = "std", feature = "use-syscall")))]
mod fixtures;

#[cfg(all(target_os = "linux", any(feature = "std", feature = "use-syscall")))]
mod host {
    use super::fixtures::compile;
    use elf_loader::{
        Error, LinkContext, Linker, Result,
        error::LinkerError,
        image::{ModuleHandle, SyntheticModule, SyntheticSymbol},
        input::PathBuf,
        linker::{KeyResolver, ResolveInput, ResolveRequest, ResolvedKey, SearchPathResolver},
    };

    struct HostImports(ModuleHandle);

    impl KeyResolver for HostImports {
        type Root = PathBuf;

        fn root_key<'a>(&self, root: &'a PathBuf) -> &'a [u8] {
            root.as_bytes()
        }

        fn resolve<'cfg>(&self, req: ResolveRequest<'_, PathBuf>) -> Result<ResolvedKey<'cfg>> {
            match req.input() {
                ResolveInput::Dependency {
                    needed: b"libpoints.so",
                } => Ok(ResolvedKey::module(self.0.clone(), [])),
                _ => SearchPathResolver::new().resolve(req),
            }
        }
    }

    #[test]
    fn synthetic_dependency() -> Result<()> {
        compile(
            "tests/fixtures/points.c",
            "libpoints.so",
            &["-shared", "-fPIC"],
        );
        let path = compile(
            "tests/fixtures/host_plugin.c",
            "host_plugin.so",
            &["-shared", "-fPIC", "-L.", "-lpoints"],
        );
        let mut context = LinkContext::for_process();
        let linker = Linker::new().with_resolver(SearchPathResolver::new());
        let error = linker.run().load(&mut context, path.clone()).unwrap_err();
        assert!(matches!(
            error,
            Error::Linker(LinkerError::UnresolvedDependency(_))
        ));
        assert!(context.is_empty());

        extern "C" fn points() -> i32 {
            2
        }
        let base = |value: &'static i32| {
            SyntheticSymbol::object(
                c"base_points",
                std::ptr::from_ref(value).cast(),
                size_of::<i32>(),
            )
        };
        let host = ModuleHandle::from(SyntheticModule::new(
            context.domain(),
            "libpoints.so",
            [
                base(&40).with_version("V2", true),
                base(&10).with_version("V1", false),
                SyntheticSymbol::function(c"points", points as *const ()),
            ],
        ));
        #[cfg(feature = "version")]
        {
            let old = unsafe { host.get_version::<*const i32>("base_points", "V1") }?.unwrap();
            assert_eq!(unsafe { **old }, 10);
        }

        let linker = Linker::new().with_resolver(HostImports(host));
        let plugin = linker.run().load(&mut context, path)?;
        let module = context.module(plugin.root())?;
        let score = unsafe { module.get::<extern "C" fn() -> i32>("score") }?.unwrap();
        assert_eq!(score(), 42);
        drop(plugin.release(&mut context)?);
        assert!(context.is_empty());
        Ok(())
    }
}

#[test]
fn generated_elf32() -> Result<()> {
    let image = DsoBuilder::<X86Arch>::new("settings.so")
        .with_text(*b"v1.2")
        .export(DsoExport::object("revision", 1, 3))
        .build()?;
    let domain = Domain::new(AddressSpaceId::PROCESS, NativeCodeExecutor);
    let raw = Loader::new()
        .with_arch::<X86Arch>()
        .with_mmap(AllocMmap::new())
        .run(domain)
        .load(ElfBinary::new(image.soname, &image.bytes))?;
    let library = Relocator::new().run(raw).relocate()?.into_dylib().unwrap();
    let revision = unsafe { library.get::<*const [u8; 3]>("revision") }?.unwrap();
    assert_eq!(unsafe { &**revision }, b"1.2");
    Ok(())
}
