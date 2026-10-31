use elf_loader::{Error, Loader, error::TlsError, input::ElfBinary};
use std::fs;

#[test]
fn requires_resolver() {
    let path = crate::fixture::build();
    let bytes = fs::read(path).expect("failed to read TLS fixture");

    let error = Loader::new()
        .run(elf_loader::Domain::native(
            elf_loader::AddressSpaceId::PROCESS,
        ))
        .load_dylib(ElfBinary::new("tls.so", &bytes))
        .expect_err("TLS image should fail to load without a resolver");
    assert!(matches!(error, Error::Tls(TlsError::ResolverUnsupported)));

    // Without a thread-storage backend, the default resolver must also reject
    // managed dynamic TLS instead of retaining state under a reusable thread ID.
    #[cfg(not(feature = "std"))]
    {
        let error = Loader::new()
            .run(
                elf_loader::Domain::native(elf_loader::AddressSpaceId::PROCESS)
                    .with_tls(elf_loader::tls::DefaultTlsResolver::new())
                    .unwrap(),
            )
            .load_dylib(ElfBinary::new("tls.so", &bytes))
            .expect_err("managed dynamic TLS requires thread storage");
        assert!(matches!(error, Error::Tls(TlsError::ResolverUnsupported)));
    }
}
