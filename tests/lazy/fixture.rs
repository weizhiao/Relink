use std::{fs, sync::OnceLock};

use crate::fixture_build::FixtureBuild;

pub(crate) struct Fixtures {
    pub(crate) provider: Vec<u8>,
    pub(crate) consumer: Vec<u8>,
    pub(crate) now: Vec<u8>,
}

pub(crate) fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(build)
}

fn build() -> Fixtures {
    let build = FixtureBuild::rust("tests/lazy/fixtures", "lazy");
    let provider = build.rust_cdylib("provider.rs", "lazy_provider", &[], |_| {});

    let build_consumer = |name: &str, mode: &str| {
        build.rust_cdylib("consumer.rs", name, &[provider.as_path()], |command| {
            command
                .env("RUSTC_BOOTSTRAP", "1")
                .arg("-Z")
                .arg("plt=yes")
                .arg("-C")
                .arg("link-arg=-z")
                .arg("-C")
                .arg(format!("link-arg={mode}"))
                .arg("-C")
                .arg("link-arg=-rpath")
                .arg("-C")
                .arg("link-arg=$ORIGIN")
                .arg("-L")
                .arg(format!("native={}", build.output("").display()))
                .arg("-l")
                .arg("dylib=lazy_provider");
        })
    };
    let consumer = build_consumer("lazy_consumer", "lazy");
    let now = build_consumer("lazy_now", "now");

    Fixtures {
        provider: fs::read(provider).expect("failed to read lazy provider"),
        consumer: fs::read(consumer).expect("failed to read lazy consumer"),
        now: fs::read(now).expect("failed to read bind-now consumer"),
    }
}
