use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

enum Compiler {
    Rust,
    C,
}

pub(crate) struct FixtureBuild {
    source_dir: PathBuf,
    output_dir: PathBuf,
    compiler: String,
    rust_target: Option<String>,
}

#[allow(dead_code)]
impl FixtureBuild {
    pub(crate) fn rust(source_dir: &str, output_dir: &str) -> Self {
        Self::new(source_dir, output_dir, Compiler::Rust)
    }

    pub(crate) fn c(source_dir: &str, output_dir: &str) -> Self {
        Self::new(source_dir, output_dir, Compiler::C)
    }

    fn new(source_dir: &str, output_dir: &str, compiler: Compiler) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target = target();
        let (compiler, rust_target) = match compiler {
            Compiler::Rust => (
                env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()),
                target.clone(),
            ),
            Compiler::C => (c_compiler(target.as_deref()), None),
        };
        let output_dir = root
            .join("target/test-fixtures")
            .join(target.unwrap_or_else(|| "native".to_owned()))
            .join(output_dir);
        fs::create_dir_all(&output_dir).expect("failed to create test fixture directory");

        Self {
            source_dir: root.join(source_dir),
            output_dir,
            compiler,
            rust_target,
        }
    }

    fn source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.source_dir.join(name)
    }

    pub(crate) fn output(&self, name: impl AsRef<Path>) -> PathBuf {
        self.output_dir.join(name)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.compiler);
        if let Some(target) = &self.rust_target {
            command.arg("--target").arg(target);
        }
        command
    }

    pub(crate) fn compile(
        &self,
        source: impl AsRef<Path>,
        output: impl AsRef<Path>,
        dependencies: &[&Path],
        configure: impl FnOnce(&mut Command),
    ) -> PathBuf {
        let source = self.source(source);
        let output = self.output(output);
        if self.needs_rebuild(
            &output,
            std::iter::once(source.as_path()).chain(dependencies.iter().copied()),
        ) {
            let mut command = self.command();
            command.arg(&source);
            configure(&mut command);
            command.arg("-o").arg(&output);
            self.run(&mut command, &format!("compile {}", output.display()));
        }
        output
    }

    pub(crate) fn rust_cdylib(
        &self,
        source: impl AsRef<Path>,
        name: &str,
        dependencies: &[&Path],
        configure: impl FnOnce(&mut Command),
    ) -> PathBuf {
        self.compile(source, format!("lib{name}.so"), dependencies, |command| {
            command
                .arg("--crate-type=cdylib")
                .arg("--crate-name")
                .arg(name)
                .arg("-O")
                .arg("-C")
                .arg("panic=abort")
                .arg("-C")
                .arg("linker=rust-lld");
            configure(command);
        })
    }

    pub(crate) fn c_shared(
        &self,
        source: impl AsRef<Path>,
        output: impl AsRef<Path>,
        dependencies: &[&Path],
        configure: impl FnOnce(&mut Command),
    ) -> PathBuf {
        self.compile(source, output, dependencies, |command| {
            command
                .arg("-shared")
                .arg("-fPIC")
                .arg("-fno-stack-protector")
                .arg("-nostdlib");
            configure(command);
        })
    }

    fn run(&self, command: &mut Command, step: &str) {
        let status = command
            .status()
            .unwrap_or_else(|error| panic!("failed to spawn command for {step}: {error}"));
        assert!(status.success(), "command failed while trying to {step}");
    }

    fn needs_rebuild(
        &self,
        output: &Path,
        inputs: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> bool {
        let Ok(output_time) = output.metadata().and_then(|metadata| metadata.modified()) else {
            return true;
        };
        inputs.into_iter().any(|input| {
            input
                .as_ref()
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map_or(true, |input_time| input_time > output_time)
        })
    }
}

fn c_compiler(target: Option<&str>) -> String {
    if let Ok(compiler) = env::var("CC")
        && !compiler.is_empty()
    {
        return compiler;
    }

    let candidates: &[&str] = match target {
        Some("aarch64-unknown-linux-gnu") => {
            &["aarch64-linux-gnu-gcc", "aarch64-unknown-linux-gnu-gcc"]
        }
        Some("arm-unknown-linux-gnueabihf") => {
            &["arm-unknown-linux-gnueabihf-gcc", "arm-linux-gnueabihf-gcc"]
        }
        Some("i586-unknown-linux-gnu") => &["i686-linux-gnu-gcc", "i586-linux-gnu-gcc"],
        Some("loongarch64-unknown-linux-gnu") => &[
            "loongarch64-unknown-linux-gnu-gcc",
            "loongarch64-linux-gnu-gcc",
        ],
        Some("riscv64gc-unknown-linux-gnu") => {
            &["riscv64-linux-gnu-gcc", "riscv64-unknown-linux-gnu-gcc"]
        }
        _ => &["cc"],
    };
    candidates
        .iter()
        .find(|compiler| command_exists(compiler))
        .unwrap_or_else(|| panic!("no C compiler found for {}", target.unwrap_or("host")))
        .to_string()
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|directory| directory.join(command).is_file())
    })
}

fn target() -> Option<String> {
    env::var("TARGET")
        .or_else(|_| env::var("CARGO_BUILD_TARGET"))
        .ok()
        .filter(|target| !target.is_empty())
        .or_else(|| {
            match env::consts::ARCH {
                "x86_64" => Some("x86_64-unknown-linux-gnu"),
                "x86" => Some("i586-unknown-linux-gnu"),
                "aarch64" => Some("aarch64-unknown-linux-gnu"),
                "riscv64" => Some("riscv64gc-unknown-linux-gnu"),
                "loongarch64" => Some("loongarch64-unknown-linux-gnu"),
                "arm" => Some("arm-unknown-linux-gnueabihf"),
                _ => None,
            }
            .map(str::to_owned)
        })
}
