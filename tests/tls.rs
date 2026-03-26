mod support;

#[cfg(feature = "tls")]
use support::binding::{BindingFixture, BindingMode};

#[cfg(feature = "tls")]
#[test]
fn tls_values_are_thread_local() {
    let scenario = BindingFixture::new().load(BindingMode::Eager);
    scenario.assert_tls_values_are_thread_local();
}
