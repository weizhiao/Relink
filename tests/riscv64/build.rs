use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

const TARGET_TRIPLE: &str = "riscv64gc-unknown-linux-gnu";
const DEFAULT_LINKER: &str = "riscv64-linux-gnu-gcc";
const DEFAULT_CFLAGS: &str = "-march=rv64gc -mabi=lp64d";
const FIXTURES: &[&str] = &[
    "a.c",
    "b.c",
    "test_call.c",
    "test_globals.c",
    "test_branches.c",
    "test_hi_lo.c",
    "test_pointers.c",
    "test_32bit.c",
    "test_main.c",
];

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if target != TARGET_TRIPLE {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("tests/riscv64 should live under the workspace root");
    let test_root = env::var_os("ELF_TEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.to_path_buf());
    let output_dir = test_root.join("target").join("riscv64-test");
    let fixtures_dir = manifest_dir.join("fixtures");

    std::fs::create_dir_all(&output_dir).expect("failed to create fixture output dir");

    let linker = env_var(&[
        "RISCV64_LINKER",
        "CC_riscv64gc_unknown_linux_gnu",
        "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER",
        "CC",
    ])
    .unwrap_or_else(|| DEFAULT_LINKER.to_owned());
    let cflags = env::var("RISCV64_CFLAGS").unwrap_or_else(|_| DEFAULT_CFLAGS.to_owned());

    for fixture in FIXTURES {
        let src = fixtures_dir.join(fixture);
        let obj = output_dir.join(
            Path::new(fixture)
                .with_extension("o")
                .file_name()
                .expect("object file name"),
        );
        println!("cargo:rerun-if-changed={}", src.display());

        let mut cmd = Command::new(&linker);
        cmd.args(cflags.split_whitespace());
        cmd.arg("-fPIC").arg("-c").arg(&src).arg("-o").arg(&obj);

        let status = cmd.status().unwrap_or_else(|err| {
            panic!(
                "failed to spawn fixture compiler `{linker}` for {}: {err}",
                src.display()
            )
        });
        if !status.success() {
            panic!(
                "fixture compiler `{linker}` failed while building {}",
                src.display()
            );
        }
    }
}

fn env_var(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.is_empty()))
}
