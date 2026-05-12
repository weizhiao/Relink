#![allow(dead_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::SystemTime,
};

use elf_loader::{
    input::Path as ElfPath,
    linker::{CandidateRequest, SearchPathResolver},
};

const RUST_FIXTURES: [(&str, &str); 3] = [("liba", "a"), ("libb", "b"), ("libc", "c")];
static FIXTURE_BUILD_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct FixturePaths {
    pub(crate) liba: PathBuf,
    pub(crate) libb: PathBuf,
    pub(crate) libc: PathBuf,
    pub(crate) a_object: PathBuf,
    pub(crate) b_object: PathBuf,
    pub(crate) c_object: PathBuf,
    pub(crate) exec_a: PathBuf,
}

impl FixturePaths {
    fn new(rust_target_dir: PathBuf, exec_target_dir: PathBuf) -> Self {
        Self {
            liba: rust_target_dir.join("liba.so"),
            libb: rust_target_dir.join("libb.so"),
            libc: rust_target_dir.join("libc.so"),
            a_object: rust_target_dir.join("a.o"),
            b_object: rust_target_dir.join("b.o"),
            c_object: rust_target_dir.join("c.o"),
            exec_a: exec_target_dir.join("exec_a"),
        }
    }

    pub(crate) fn liba_str(&self) -> &str {
        self.liba
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn libb_str(&self) -> &str {
        self.libb
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn libc_str(&self) -> &str {
        self.libc
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn a_object_str(&self) -> &str {
        self.a_object
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn c_object_str(&self) -> &str {
        self.c_object
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }
}

pub(crate) fn ensure_all() -> FixturePaths {
    ensure_scope(FixtureScope::All);
    FixturePaths::new(rust_target_dir(), exec_target_dir())
}

pub(crate) fn ensure_exec_a() -> PathBuf {
    ensure_scope(FixtureScope::ExecA);
    exec_target_dir().join("exec_a")
}

pub(crate) fn search_path_resolver() -> SearchPathResolver {
    let mut resolver = SearchPathResolver::new();
    resolver.push_search_dir_provider(|request, out| {
        let CandidateRequest::Dependency {
            requested,
            origin,
            runpath,
            rpath,
            ..
        } = request
        else {
            return Ok(());
        };

        if requested.has_dir_separator() {
            return Ok(());
        }

        if let Some(path_list) = runpath.or(rpath) {
            for dir in path_list.split(':') {
                if !dir.is_empty() {
                    out.push(ElfPath::expand_origin(dir, origin));
                }
            }
        }

        Ok(())
    });
    resolver
}

enum FixtureScope {
    All,
    ExecA,
}

fn ensure_scope(scope: FixtureScope) {
    if cfg!(windows) {
        panic!("ELF example fixtures are not supported on Windows");
    }

    let _guard = FIXTURE_BUILD_LOCK
        .lock()
        .expect("fixture build lock must not be poisoned");

    let rust_target_dir = rust_target_dir();
    let exec_target_dir = exec_target_dir();
    fs::create_dir_all(&rust_target_dir).expect("failed to create target directory for fixtures");
    fs::create_dir_all(&exec_target_dir)
        .expect("failed to create target directory for executable fixtures");

    match scope {
        FixtureScope::All => {
            build_rust_fixtures(&rust_target_dir);
            build_exec_fixture(&exec_target_dir);
        }
        FixtureScope::ExecA => build_exec_fixture(&exec_target_dir),
    }
}

fn build_rust_fixtures(target_dir: &Path) {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let rust_target = rust_fixture_target();

    for (filename, crate_name) in RUST_FIXTURES {
        let source = fixture_dir().join(format!("{filename}.rs"));
        let dylib = target_dir.join(format!("lib{crate_name}.so"));
        let dylib_dep = rust_fixture_dylib_dependency(crate_name);
        let needs_dylib_rebuild = needs_rebuild(&dylib, [&source])
            || dylib_dep.is_some_and(|dep| !dylib_mentions_needed(&dylib, dep))
            || !dylib_mentions_origin_runpath(&dylib);
        if needs_dylib_rebuild {
            let mut cmd = Command::new(&rustc);
            cmd.arg(&source)
                .arg("--crate-type=cdylib")
                .arg("--crate-name")
                .arg(crate_name)
                .arg("-O")
                .arg("-C")
                .arg("panic=abort")
                .arg("--out-dir")
                .arg(target_dir)
                .arg("-C")
                .arg("linker=rust-lld")
                .arg("-C")
                .arg("link-arg=--emit-relocs")
                .arg("-C")
                .arg("link-arg=-rpath")
                .arg("-C")
                .arg("link-arg=$ORIGIN");
            if let Some(target) = rust_target.as_deref() {
                cmd.arg("--target").arg(target);
            }
            if let Some(dep) = dylib_dep {
                cmd.arg("-L")
                    .arg(format!("native={}", target_dir.display()))
                    .arg("-l")
                    .arg(format!("dylib={dep}"));
            }
            run(&mut cmd, &format!("compile {filename}.so"));
        }

        let object = target_dir.join(format!("{crate_name}.o"));
        if needs_rebuild(&object, [&source]) {
            let mut cmd = Command::new(&rustc);
            cmd.arg(&source)
                .arg("--crate-type=lib")
                .arg("--emit=obj")
                .arg("-o")
                .arg(&object)
                .arg("-O")
                .arg("-C")
                .arg("panic=abort");
            if let Some(target) = rust_target.as_deref() {
                cmd.arg("--target").arg(target);
            }
            run(&mut cmd, &format!("compile {filename}.o"));
        }
    }
}

fn rust_fixture_dylib_dependency(crate_name: &str) -> Option<&'static str> {
    match crate_name {
        "b" => Some("a"),
        "c" => Some("b"),
        _ => None,
    }
}

fn dylib_mentions_needed(dylib: &Path, dep: &str) -> bool {
    let needed = format!("lib{dep}.so");
    fs::read(dylib)
        .map(|bytes| {
            bytes
                .windows(needed.len())
                .any(|window| window == needed.as_bytes())
        })
        .unwrap_or(false)
}

fn dylib_mentions_origin_runpath(dylib: &Path) -> bool {
    fs::read(dylib)
        .map(|bytes| {
            bytes
                .windows(b"$ORIGIN".len())
                .any(|window| window == b"$ORIGIN")
        })
        .unwrap_or(false)
}

fn build_exec_fixture(target_dir: &Path) {
    let source = fixture_dir().join("exec_a.c");
    let output = target_dir.join("exec_a");
    if !needs_rebuild(&output, [&source]) {
        return;
    }

    let compiler = env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let mut cmd = Command::new(compiler);
    cmd.arg(&source)
        .arg("-no-pie")
        .arg("-fno-pic")
        .arg("-o")
        .arg(&output);

    run(&mut cmd, "compile exec_a");
}

fn run(cmd: &mut Command, step: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|err| panic!("failed to spawn command for {step}: {err}"));
    assert!(status.success(), "command failed while trying to {step}");
}

fn needs_rebuild(output: &Path, inputs: impl IntoIterator<Item = impl AsRef<Path>>) -> bool {
    let Ok(metadata) = output.metadata() else {
        return true;
    };
    let Ok(output_mtime) = metadata.modified() else {
        return true;
    };

    inputs
        .into_iter()
        .map(|input| input.as_ref().to_path_buf())
        .any(|input| modified_time(&input).unwrap_or(SystemTime::UNIX_EPOCH) > output_mtime)
}

fn modified_time(path: &Path) -> Option<SystemTime> {
    path.metadata().ok()?.modified().ok()
}

fn rust_target_dir() -> PathBuf {
    let dir_name = rust_fixture_target().unwrap_or_else(|| "native".to_owned());
    manifest_dir().join("target/fixtures").join(dir_name)
}

fn exec_target_dir() -> PathBuf {
    manifest_dir().join("target")
}

fn rust_fixture_target() -> Option<String> {
    env::var("TARGET")
        .or_else(|_| env::var("CARGO_BUILD_TARGET"))
        .ok()
        .filter(|target| !target.is_empty())
        .or_else(|| default_rust_fixture_target().map(str::to_owned))
}

fn default_rust_fixture_target() -> Option<&'static str> {
    if !cfg!(all(target_os = "linux", target_env = "gnu")) {
        return None;
    }

    match env::consts::ARCH {
        "x86_64" => Some("x86_64-unknown-linux-gnu"),
        "x86" => Some("i586-unknown-linux-gnu"),
        "aarch64" => Some("aarch64-unknown-linux-gnu"),
        "riscv64" => Some("riscv64gc-unknown-linux-gnu"),
        "loongarch64" => Some("loongarch64-unknown-linux-gnu"),
        "arm" => Some("arm-unknown-linux-gnueabihf"),
        _ => None,
    }
}

fn fixture_dir() -> PathBuf {
    manifest_dir().join("examples/fixtures")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
