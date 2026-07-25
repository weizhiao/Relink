use std::{
    env,
    path::PathBuf,
    process::{Command, ExitStatus},
};

fn run(command: &mut Command) -> ExitStatus {
    command
        .status()
        .unwrap_or_else(|error| panic!("failed to run {command:?}: {error}"))
}

fn main() {
    println!("cargo:rerun-if-changed=fixture.c");
    println!("cargo:rerun-if-env-changed=XTENSA_GCC");

    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("fixture.so");
    let compiler = env::var_os("XTENSA_GCC").unwrap_or_else(|| "xtensa-esp32-elf-gcc".into());
    let status = run(Command::new(compiler)
        .args([
            "-shared",
            "-nostdlib",
            "-fPIC",
            "-O2",
            "-Wl,--hash-style=gnu",
            "-Wl,-soname,fixture.so",
            "-o",
        ])
        .arg(&output)
        .arg("fixture.c"));
    assert!(status.success(), "failed to build Xtensa ELF fixture");
}
