#![allow(dead_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::SystemTime,
};

use elf_loader::linker::SearchPathResolver;

const RUST_FIXTURES: [&str; 3] = ["base", "middle", "leaf"];
static FIXTURE_BUILD_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct FixturePaths {
    pub(crate) base: PathBuf,
    pub(crate) middle: PathBuf,
    pub(crate) leaf: PathBuf,
    pub(crate) base_object: PathBuf,
    pub(crate) middle_object: PathBuf,
    pub(crate) leaf_object: PathBuf,
    pub(crate) native_exec: PathBuf,
}

impl FixturePaths {
    fn new(rust_target_dir: PathBuf, exec_target_dir: PathBuf) -> Self {
        Self {
            base: rust_target_dir.join("libbase.so"),
            middle: rust_target_dir.join("libmiddle.so"),
            leaf: rust_target_dir.join("libleaf.so"),
            base_object: rust_target_dir.join("base.o"),
            middle_object: rust_target_dir.join("middle.o"),
            leaf_object: rust_target_dir.join("leaf.o"),
            native_exec: exec_target_dir.join("native_exec"),
        }
    }

    pub(crate) fn base_str(&self) -> &str {
        self.base
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn middle_str(&self) -> &str {
        self.middle
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn leaf_str(&self) -> &str {
        self.leaf
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn base_object_str(&self) -> &str {
        self.base_object
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }

    pub(crate) fn leaf_object_str(&self) -> &str {
        self.leaf_object
            .to_str()
            .expect("fixture path must be valid UTF-8")
    }
}

pub(crate) fn ensure_all() -> FixturePaths {
    ensure_scope(FixtureScope::All);
    FixturePaths::new(rust_target_dir(), exec_target_dir())
}

pub(crate) fn ensure_native_exec() -> PathBuf {
    ensure_scope(FixtureScope::NativeExec);
    exec_target_dir().join("native_exec")
}

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

enum FixtureScope {
    All,
    NativeExec,
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
        FixtureScope::NativeExec => build_exec_fixture(&exec_target_dir),
    }
}

fn build_rust_fixtures(target_dir: &Path) {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let rust_target = rust_fixture_target();

    for name in RUST_FIXTURES {
        let source = fixture_dir().join("deps").join(format!("{name}.rs"));
        let dylib = target_dir.join(format!("lib{name}.so"));
        let dylib_dep = rust_fixture_dylib_dependency(name);
        let needs_dylib_rebuild = needs_rebuild(&dylib, [&source])
            || dylib_dep.is_some_and(|dep| !dylib_mentions_needed(&dylib, dep))
            || !dylib_mentions_origin_runpath(&dylib);
        if needs_dylib_rebuild {
            let mut cmd = Command::new(&rustc);
            cmd.arg(&source)
                .arg("--crate-type=cdylib")
                .arg("--crate-name")
                .arg(name)
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
            run(&mut cmd, &format!("compile {name}.so"));
        }

        let object = target_dir.join(format!("{name}.o"));
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
            run(&mut cmd, &format!("compile {name}.o"));
        }
    }
}

fn rust_fixture_dylib_dependency(name: &str) -> Option<&'static str> {
    match name {
        "middle" => Some("base"),
        "leaf" => Some("middle"),
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
    let source = fixture_dir().join("native_exec.c");
    let output = target_dir.join("native_exec");
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

    run(&mut cmd, "compile native_exec");
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
    manifest_dir().join("examples/support/fixtures")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
