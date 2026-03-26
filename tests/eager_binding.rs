mod support;

use support::binding::{BindingFixture, BindingMode};

#[test]
fn eager_binding_matches_fixture() {
    let scenario = BindingFixture::new().load(BindingMode::Eager);

    scenario.assert_single_dependency();
    scenario.assert_non_plt_relocations();
    scenario.assert_relative_relocations();
    scenario.assert_eager_jump_slots();
    scenario.assert_plt_helpers_work();
    #[cfg(feature = "tls")]
    scenario.assert_tls_relocations();
}
