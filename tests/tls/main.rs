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
fn rejects_unsupported_managed_storage() {
    use elf_loader::{
        Error,
        error::TlsError,
        tls::{DefaultTlsResolver, TlsInfo, TlsRequest, TlsResolver},
    };

    let error = DefaultTlsResolver::new()
        .register(
            TlsInfo {
                vaddr: 0,
                filesz: 0,
                memsz: 4,
                align: 4,
            },
            TlsRequest::Dynamic,
        )
        .expect_err("managed dynamic TLS requires a supported thread-storage backend");
    assert!(matches!(error, Error::Tls(TlsError::ResolverUnsupported)));
}
