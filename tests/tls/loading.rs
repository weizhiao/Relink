use elf_loader::{Error, Loader, error::TlsError, input::ElfBinary};
use std::fs;

#[test]
fn requires_resolver() {
    let path = crate::fixture::build();
    let bytes = fs::read(path).expect("failed to read TLS fixture");

    let error = Loader::new()
        .load_dylib(ElfBinary::new("tls.so", &bytes))
        .expect_err("TLS image should fail to load without a resolver");
    assert!(matches!(error, Error::Tls(TlsError::ResolverUnsupported)));
}
