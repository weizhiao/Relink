use std::{fs, path::Path, sync::OnceLock};

#[cfg(any(feature = "libc", feature = "use-syscall"))]
use elf_loader::linker::SearchPathResolver;
#[cfg(any(feature = "libc", feature = "use-syscall"))]
use std::path::PathBuf;

use crate::fixture_build::FixtureBuild;

pub(crate) struct Fixtures {
    pub(crate) provider: Vec<u8>,
    pub(crate) dependent: Vec<u8>,
    pub(crate) plain: Vec<u8>,
    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    pub(crate) exec: Vec<u8>,
    #[cfg(any(feature = "libc", feature = "use-syscall"))]
    pub(crate) provider_path: PathBuf,
    #[cfg(any(feature = "libc", feature = "use-syscall"))]
    pub(crate) root_path: PathBuf,
}

pub(crate) fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(build)
}

#[cfg(any(feature = "libc", feature = "use-syscall"))]
pub(crate) fn search_path_resolver<K>() -> SearchPathResolver<K> {
    let mut resolver = SearchPathResolver::new();
    resolver.push_search_dir_provider(|request, out| {
        if let Some(dirs) = request.runpath() {
            out.extend(dirs);
        } else if let Some(dirs) = request.rpath() {
            out.extend(dirs);
        }
        Ok(())
    });
    resolver
}

fn build() -> Fixtures {
    let build = FixtureBuild::rust("tests/linker/fixtures", "linker");
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
    let provider_path = dylib("provider", None);
    let dependent_path = dylib("dependent", Some(("provider", &provider_path)));
    #[cfg(any(feature = "libc", feature = "use-syscall"))]
    let root_path = dylib("root", Some(("dependent", &dependent_path)));

    let plain = build.rust_cdylib("plain.rs", "plain", &[], |_| {});

    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    let exec = build.compile(
        "exec.rs",
        "dynamic_exec",
        &[provider_path.as_path()],
        |command| {
            command
                .arg("--crate-type=bin")
                .arg("--crate-name")
                .arg("dynamic_exec")
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
                .arg("-C")
                .arg("link-arg=-rpath")
                .arg("-C")
                .arg("link-arg=$ORIGIN")
                .arg("-L")
                .arg(format!("native={}", build.output("").display()))
                .arg("-l")
                .arg("dylib=provider");
        },
    );

    Fixtures {
        provider: fs::read(&provider_path).expect("failed to read linker provider fixture"),
        dependent: fs::read(dependent_path).expect("failed to read linker dependent fixture"),
        plain: fs::read(plain).expect("failed to read linker plain fixture"),
        #[cfg(any(
            feature = "use-syscall",
            all(any(target_os = "linux", target_os = "android"), feature = "libc")
        ))]
        exec: fs::read(exec).expect("failed to read linker executable fixture"),
        #[cfg(any(feature = "libc", feature = "use-syscall"))]
        provider_path,
        #[cfg(any(feature = "libc", feature = "use-syscall"))]
        root_path,
    }
}
