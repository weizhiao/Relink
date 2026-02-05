use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let fixture_path = PathBuf::from("examples/fixtures");
    if !fixture_path.exists() {
        return;
    }

    println!("cargo:rerun-if-changed=examples/fixtures");
    println!("cargo:rerun-if-changed=tests/fixtures");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();

    if target.contains("windows") {
        // Windows build not supported for fixtures
        return;
    }

    // Expose the output directory to tests
    println!("cargo:rustc-env=TEST_ARTIFACTS={}", out_dir.display());

    // Build steps for fixtures have been simplified: all non-test fixtures moved
    // to `examples/fixtures`. Only `exec_a` is built here for tests. Examples
    // should build their own fixtures from `examples/fixtures` as needed.

    // Re-create small set of runtime fixtures required by doctests/examples
    // (liba/libb/libc) from `examples/fixtures/rust` so doctests that load
    // `liba.so` continue to work.
    let rust_code = [("liba", "a"), ("libb", "b"), ("libc", "c")];
    for (filename, crate_name) in &rust_code {
        let src = format!("examples/fixtures/{}.rs", filename);
        let mut cmd = Command::new("rustc");
        cmd.arg(&src)
            .arg("--crate-type=cdylib")
            .arg("--crate-name")
            .arg(crate_name)
            .arg("--target")
            .arg(&target)
            .arg("-O")
            .arg("-C")
            .arg("panic=abort")
            .arg("--out-dir")
            .arg(&out_dir)
            .arg("-C")
            .arg("linker=rust-lld");

        let status = cmd.status().expect("Failed to run rustc");
        assert!(status.success(), "Failed to compile {}", filename);
    }

    // Build .o files for object loading examples
    for (filename, crate_name) in &rust_code {
        let src = format!("examples/fixtures/{}.rs", filename);
        let mut cmd = Command::new("rustc");
        cmd.arg(&src)
            .arg("--crate-type=lib")
            .arg("--emit=obj")
            .arg("-o")
            .arg(out_dir.join(format!("{}.o", crate_name)))
            .arg("--target")
            .arg(&target)
            .arg("-O")
            .arg("-C")
            .arg("panic=abort");

        let status = cmd.status().expect("Failed to run rustc");
        assert!(status.success(), "Failed to compile {} to object", filename);
    }

    // Get the compiler/linker to use
    let cc_target = if target == "aarch64-unknown-none" {
        "aarch64-unknown-linux-gnu"
    } else {
        &target
    };
    let compiler = cc::Build::new().target(cc_target).get_compiler();
    let cc_path = compiler.path();

    let exec_a_c = "tests/fixtures/c/exec_a.c";
    let exec_a = out_dir.join("exec_a");
    let mut cmd = Command::new(cc_path);
    cmd.arg(exec_a_c)
        .arg("-no-pie")
        .arg("-fno-pic")
        .arg("-o")
        .arg(&exec_a);

    for arg in compiler.args() {
        cmd.arg(arg);
    }
    let _ = cmd.status();

    // Copy built files to target/ for examples/doctests to find
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target_dir = manifest_dir.join("target");
    if !target_dir.exists() {
        let _ = std::fs::create_dir_all(&target_dir);
    }

    // Copy .so files
    for (_, crate_name) in &rust_code {
        let name = format!("lib{}.so", crate_name);
        let src = out_dir.join(&name);
        let dest = target_dir.join(&name);
        let _ = std::fs::copy(&src, &dest);
    }

    // Copy .o files
    for (_, crate_name) in &rust_code {
        let name = format!("{}.o", crate_name);
        let src = out_dir.join(&name);
        let dest = target_dir.join(&name);
        let _ = std::fs::copy(&src, &dest);
    }

    // Copy exec_a
    let dest = target_dir.join("exec_a");
    let _ = std::fs::copy(&exec_a, &dest);
}
