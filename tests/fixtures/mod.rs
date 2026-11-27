use elf_loader::input::{Path as ElfPath, PathBuf};
use std::{env, fs, path::Path, process::Command};

pub fn compile(source: &str, output: &str, flags: &[&str]) -> PathBuf {
    let dir = Path::new(env!("OUT_DIR")).join(format!("fixtures-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let compiler = env::var("CC").unwrap_or_else(|_| match option_env!("CROSS_TOOLCHAIN_PREFIX") {
        Some(prefix) => format!("{prefix}gcc"),
        None => "cc".into(),
    });
    let mut command = Command::new(compiler);
    command
        .current_dir(&dir)
        .args(["-fno-stack-protector", "-nostdlib"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(source))
        .args(flags)
        .arg("-o")
        .arg(output);
    let status = command
        .status()
        .unwrap_or_else(|e| panic!("{command:?}: {e}"));
    assert!(status.success(), "{command:?} exited with {status}");
    ElfPath::new(dir.join(output).as_os_str().as_encoded_bytes()).into()
}
