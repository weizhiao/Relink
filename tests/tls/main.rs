#[cfg(not(windows))]
mod fixture;
#[cfg(not(windows))]
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
#[cfg(not(windows))]
mod loading;

#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
mod relocation;
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
mod support;
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
mod thread;

#[cfg(all(feature = "std", target_os = "linux", target_env = "gnu"))]
mod destruction;

#[cfg(not(all(feature = "std", any(target_os = "linux", target_os = "android"))))]
#[test]
fn rejects_all_default_registrations_without_thread_storage() {
    use elf_loader::{
        Error,
        error::TlsError,
        tls::{
            DefaultTlsResolver, TlsContext, TlsInfo, TlsProvider, TlsRequest, TlsResolver,
            TlsTpOffset,
        },
    };

    let resolver = DefaultTlsResolver::new();
    let info = TlsInfo {
        vaddr: 0,
        filesz: 0,
        memsz: 4,
        align: 4,
    };
    for request in [
        TlsRequest::Dynamic,
        TlsRequest::Static(Some(TlsTpOffset::new(0))),
    ] {
        let error = resolver
            .register(info, request)
            .expect_err("all default registrations require thread storage");
        assert!(matches!(error, Error::Tls(TlsError::ResolverUnsupported)));
    }

    struct UnusedProvider;
    unsafe impl TlsProvider for UnusedProvider {
        unsafe fn get_or_init(&self, _: &TlsContext) -> elf_loader::Result<std::ptr::NonNull<u8>> {
            unreachable!("registration must fail before resolving storage")
        }

        unsafe fn get(&self, _: &TlsContext) -> Option<std::ptr::NonNull<u8>> {
            unreachable!("registration must fail before querying storage")
        }
    }
    let error = unsafe { resolver.register_provider(info, None, UnusedProvider) }
        .expect_err("external providers also require the default thread-storage backend");
    assert!(matches!(error, Error::Tls(TlsError::ResolverUnsupported)));
}
