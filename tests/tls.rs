mod support;

#[cfg(feature = "tls")]
use support::binding::{BindingFixture, BindingKind};

#[cfg(feature = "tls")]
#[test]
fn tls_values_are_thread_local() {
    let scenario = BindingFixture::new().load(BindingKind::Eager);
    scenario.assert_tls_values_are_thread_local();
}
