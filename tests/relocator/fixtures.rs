#[cfg(target_arch = "riscv64")]
use std::env;
use std::{fs, path::PathBuf, sync::OnceLock};

use crate::fixture_build::FixtureBuild;

#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
pub(crate) struct BindingFixtures {
    pub(crate) provider: Vec<u8>,
    pub(crate) consumer: Vec<u8>,
}

pub(crate) struct ScopeFixtures {
    pub(crate) provider: Vec<u8>,
    pub(crate) consumer: Vec<u8>,
    pub(crate) defining: Vec<u8>,
    pub(crate) symbolic: Vec<u8>,
}

#[cfg(all(
    not(target_arch = "loongarch64"),
    any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    )
))]
pub(crate) struct CopyFixtures {
    pub(crate) provider: Vec<u8>,
    pub(crate) executable: Vec<u8>,
}

pub(crate) struct DynamicFixtures {
    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    pub(crate) binding: BindingFixtures,
    pub(crate) scope: ScopeFixtures,
    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    pub(crate) relative: Vec<u8>,
    pub(crate) weak: Vec<u8>,
    #[cfg(all(
        not(target_arch = "loongarch64"),
        any(
            feature = "use-syscall",
            all(any(target_os = "linux", target_os = "android"), feature = "libc")
        )
    ))]
    pub(crate) copy: CopyFixtures,
    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    pub(crate) ifunc: Vec<u8>,
}

#[cfg(target_arch = "riscv64")]
pub(crate) struct Riscv64Fixtures {
    pub(crate) a: PathBuf,
    pub(crate) b: PathBuf,
    pub(crate) call: PathBuf,
    pub(crate) globals: PathBuf,
    pub(crate) hi_lo: PathBuf,
    pub(crate) pointers: PathBuf,
}

pub(crate) fn dynamic() -> &'static DynamicFixtures {
    static FIXTURES: OnceLock<DynamicFixtures> = OnceLock::new();
    FIXTURES.get_or_init(build_dynamic)
}

#[cfg(target_arch = "riscv64")]
pub(crate) fn riscv64() -> &'static Riscv64Fixtures {
    static FIXTURES: OnceLock<Riscv64Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(build_riscv64)
}

fn read(path: PathBuf) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|_| panic!("failed to read fixture {}", path.display()))
}

fn build_dynamic() -> DynamicFixtures {
    let build = FixtureBuild::c("tests/relocator/fixtures/dynamic", "relocator/dynamic");

    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    let binding = {
        let provider = build.c_shared(
            "binding/provider.c",
            "libbinding_provider.so",
            &[],
            |command| {
                command.arg("-Wl,-soname,libbinding_provider.so");
            },
        );
        let consumer = build.c_shared(
            "binding/consumer.c",
            "libbinding_consumer.so",
            &[provider.as_path()],
            |command| {
                command
                    .arg("-Wl,-z,now")
                    .arg("-Wl,-rpath,$ORIGIN")
                    .arg("-L")
                    .arg(build.output(""))
                    .arg("-lbinding_provider");
            },
        );
        BindingFixtures {
            provider: read(provider),
            consumer: read(consumer),
        }
    };

    let scope_provider = build.c_shared("scope/provider.c", "libscope_provider.so", &[], |_| {});
    let scope_consumer =
        build.c_shared("scope/consumer.c", "libscope_consumer.so", &[], |command| {
            command.arg("-Wl,-z,now");
        });
    let scope_defining =
        build.c_shared("scope/defining.c", "libscope_defining.so", &[], |command| {
            command.arg("-Wl,-z,now");
        });
    let scope_symbolic =
        build.c_shared("scope/symbolic.c", "libscope_symbolic.so", &[], |command| {
            command.arg("-Wl,-z,now").arg("-Wl,-Bsymbolic");
        });

    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    let relative = read(
        build.c_shared("relative.c", "librelative.so", &[], |command| {
            command.arg("-Wl,-z,now");
        }),
    );
    let weak = build.c_shared("weak.c", "libweak.so", &[], |command| {
        command.arg("-Wl,-z,now");
    });

    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    let ifunc = build.c_shared("ifunc.c", "libifunc.so", &[], |command| {
        command.arg("-Wl,-z,now");
    });

    #[cfg(all(
        not(target_arch = "loongarch64"),
        any(
            feature = "use-syscall",
            all(any(target_os = "linux", target_os = "android"), feature = "libc")
        )
    ))]
    let copy = {
        let provider = build.c_shared("copy/provider.c", "libcopy_provider.so", &[], |command| {
            command.arg("-Wl,-soname,libcopy_provider.so");
        });
        let executable = build.compile(
            "copy/executable.c",
            "copy_relocations",
            &[provider.as_path()],
            |command| {
                command
                    .arg("-fno-pic")
                    .arg("-fno-pie")
                    .arg("-no-pie")
                    .arg("-fno-stack-protector")
                    .arg("-nostdlib")
                    .arg("-Wl,-e,_start")
                    .arg("-Wl,-z,now")
                    .arg("-Wl,-rpath,$ORIGIN")
                    .arg("-L")
                    .arg(build.output(""))
                    .arg("-lcopy_provider");
            },
        );
        CopyFixtures {
            provider: read(provider),
            executable: read(executable),
        }
    };

    DynamicFixtures {
        #[cfg(any(
            feature = "use-syscall",
            all(any(target_os = "linux", target_os = "android"), feature = "libc")
        ))]
        binding,
        scope: ScopeFixtures {
            provider: read(scope_provider),
            consumer: read(scope_consumer),
            defining: read(scope_defining),
            symbolic: read(scope_symbolic),
        },
        #[cfg(any(
            feature = "use-syscall",
            all(any(target_os = "linux", target_os = "android"), feature = "libc")
        ))]
        relative,
        weak: read(weak),
        #[cfg(all(
            not(target_arch = "loongarch64"),
            any(
                feature = "use-syscall",
                all(any(target_os = "linux", target_os = "android"), feature = "libc")
            )
        ))]
        copy,
        #[cfg(any(
            feature = "use-syscall",
            all(any(target_os = "linux", target_os = "android"), feature = "libc")
        ))]
        ifunc: read(ifunc),
    }
}

#[cfg(target_arch = "riscv64")]
fn build_riscv64() -> Riscv64Fixtures {
    const NAMES: [&str; 6] = ["a", "b", "call", "globals", "hi_lo", "pointers"];

    let build = FixtureBuild::c("tests/relocator/fixtures/riscv64", "relocator/riscv64");
    let cflags =
        env::var("RISCV64_CFLAGS").unwrap_or_else(|_| "-march=rv64gc -mabi=lp64d".to_owned());
    for name in NAMES {
        build.compile(format!("{name}.c"), format!("{name}.o"), &[], |command| {
            command
                .args(cflags.split_whitespace())
                .arg("-fPIC")
                .arg("-c");
        });
    }

    Riscv64Fixtures {
        a: build.output("a.o"),
        b: build.output("b.o"),
        call: build.output("call.o"),
        globals: build.output("globals.o"),
        hi_lo: build.output("hi_lo.o"),
        pointers: build.output("pointers.o"),
    }
}
