mod support;

#[cfg(feature = "tls")]
use elf_loader::{Loader, tls::DefaultTlsResolver};
#[cfg(feature = "tls")]
use support::binding::{BindingFixture, BindingKind};

#[cfg(feature = "tls")]
const TLS_LOADER: Loader<(), DefaultTlsResolver> =
    Loader::new().with_tls_resolver(DefaultTlsResolver::new());

#[cfg(feature = "tls")]
#[test]
fn tls_values_are_thread_local() {
    let _loader = TLS_LOADER;
    let scenario = BindingFixture::new().load(BindingKind::Eager);
    scenario.assert_tls_values_are_thread_local();
}
