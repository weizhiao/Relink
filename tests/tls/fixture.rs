use std::path::PathBuf;

use crate::fixture_build::FixtureBuild;

pub(crate) fn build() -> PathBuf {
    let build = FixtureBuild::c("tests/tls/fixtures", "tls");
    build.c_shared("module.c", "libtls.so", &[], |command| {
        command.arg("-Wl,-soname,libtls.so");
    })
}
