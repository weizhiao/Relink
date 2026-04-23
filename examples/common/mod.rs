#![allow(dead_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

const RUST_FIXTURES: [(&str, &str); 3] = [("liba", "a"), ("libb", "b"), ("libc", "c")];

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
    fn new(target_dir: PathBuf) -> Self {
        Self {
            liba: target_dir.join("liba.so"),
            libb: target_dir.join("libb.so"),
            libc: target_dir.join("libc.so"),
            a_object: target_dir.join("a.o"),
            b_object: target_dir.join("b.o"),
            c_object: target_dir.join("c.o"),
            exec_a: target_dir.join("exec_a"),
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
    FixturePaths::new(target_dir())
}

pub(crate) fn ensure_exec_a() -> PathBuf {
    ensure_scope(FixtureScope::ExecA);
    target_dir().join("exec_a")
}

enum FixtureScope {
    All,
    ExecA,
}

fn ensure_scope(scope: FixtureScope) {
    if cfg!(windows) {
        panic!("ELF example fixtures are not supported on Windows");
    }

    let target_dir = target_dir();
    fs::create_dir_all(&target_dir).expect("failed to create target directory for fixtures");

    match scope {
        FixtureScope::All => {
            build_rust_fixtures(&target_dir);
            build_exec_fixture(&target_dir);
        }
        FixtureScope::ExecA => build_exec_fixture(&target_dir),
    }
}

fn build_rust_fixtures(target_dir: &Path) {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());

    for (filename, crate_name) in RUST_FIXTURES {
        let source = fixture_dir().join(format!("{filename}.rs"));
        let dylib = target_dir.join(format!("lib{crate_name}.so"));
        let dylib_dep = rust_fixture_dylib_dependency(crate_name);
        let needs_dylib_rebuild = needs_rebuild(&dylib, [&source])
            || dylib_dep.is_some_and(|dep| !dylib_mentions_needed(&dylib, dep));
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
                .arg("link-arg=--emit-relocs");
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

fn target_dir() -> PathBuf {
    manifest_dir().join("target")
}

fn fixture_dir() -> PathBuf {
    manifest_dir().join("examples/fixtures")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
