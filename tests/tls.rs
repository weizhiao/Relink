mod support;

use elf_loader::{Loader, tls::DefaultTlsResolver};
use support::binding::{BindingFixture, BindingKind};

const TLS_LOADER: Loader<(), DefaultTlsResolver> =
    Loader::new().with_tls_resolver(DefaultTlsResolver::new());

#[test]
fn tls_values_are_thread_local() {
    let _loader = TLS_LOADER;
    let scenario = BindingFixture::new().load(BindingKind::Eager);
    scenario.assert_tls_values_are_thread_local();
}
