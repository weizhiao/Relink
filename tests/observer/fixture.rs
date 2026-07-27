use std::{fs, path::Path, sync::OnceLock};

use crate::fixture_build::FixtureBuild;

pub(crate) struct Fixtures {
    pub(crate) provider: Vec<u8>,
    pub(crate) dependent: Vec<u8>,
    #[cfg(all(feature = "object", target_arch = "x86_64"))]
    pub(crate) provider_object: Vec<u8>,
    #[cfg(all(feature = "object", target_arch = "x86_64"))]
    pub(crate) dependent_object: Vec<u8>,
}

pub(crate) fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(build)
}

fn build() -> Fixtures {
    let build = FixtureBuild::rust("tests/observer/fixtures", "observer");
    let dylib = |name: &str, dependency: Option<(&str, &Path)>| {
        let dependencies = dependency.iter().map(|(_, path)| *path).collect::<Vec<_>>();
        build.rust_cdylib(format!("{name}.rs"), name, &dependencies, |command| {
            command
                .arg("-C")
                .arg("link-arg=--emit-relocs")
                .arg("-C")
                .arg("link-arg=-rpath")
                .arg("-C")
                .arg("link-arg=$ORIGIN");
            if let Some((dependency, _)) = dependency {
                command
                    .arg("-L")
                    .arg(format!("native={}", build.output("").display()))
                    .arg("-l")
                    .arg(format!("dylib={dependency}"));
            }
        })
    };
    let provider = dylib("provider", None);
    let dependent = dylib("dependent", Some(("provider", &provider)));

    #[cfg(all(feature = "object", target_arch = "x86_64"))]
    let object = |name: &str| {
        build.compile(format!("{name}.rs"), format!("{name}.o"), &[], |command| {
            command
                .arg("--crate-type=lib")
                .arg("--emit=obj")
                .arg("-O")
                .arg("-C")
                .arg("panic=abort");
        })
    };
    #[cfg(all(feature = "object", target_arch = "x86_64"))]
    let provider_object = object("provider");
    #[cfg(all(feature = "object", target_arch = "x86_64"))]
    let dependent_object = object("dependent");

    Fixtures {
        provider: fs::read(provider).expect("failed to read observer provider fixture"),
        dependent: fs::read(dependent).expect("failed to read observer dependent fixture"),
        #[cfg(all(feature = "object", target_arch = "x86_64"))]
        provider_object: fs::read(provider_object)
            .expect("failed to read observer provider object"),
        #[cfg(all(feature = "object", target_arch = "x86_64"))]
        dependent_object: fs::read(dependent_object)
            .expect("failed to read observer dependent object"),
    }
}
