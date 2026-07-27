use std::{fs, sync::OnceLock};

use crate::fixture_build::FixtureBuild;

pub(crate) struct Fixtures {
    pub(crate) dylib: Vec<u8>,
    pub(crate) exec: Vec<u8>,
}

pub(crate) fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(build)
}

fn build() -> Fixtures {
    let build = FixtureBuild::rust("tests/loader/fixtures", "loader");
    let dylib = build.rust_cdylib("dylib.rs", "dylib", &[], |_| {});

    let exec = build.compile("exec.rs", "exec", &[dylib.as_path()], |command| {
        command
            .arg("--crate-type=bin")
            .arg("--crate-name")
            .arg("exec")
            .arg("-O")
            .arg("-C")
            .arg("panic=abort")
            .arg("-C")
            .arg("linker=rust-lld")
            .arg("-C")
            .arg("link-arg=-no-pie")
            .arg("-C")
            .arg("link-arg=-e")
            .arg("-C")
            .arg("link-arg=_start")
            .arg("-L")
            .arg(format!("native={}", build.output("").display()))
            .arg("-l")
            .arg("dylib=dylib");
    });

    Fixtures {
        dylib: fs::read(dylib).expect("failed to read loader dylib fixture"),
        exec: fs::read(exec).expect("failed to read loader executable fixture"),
    }
}
