//! General-dynamic TLS access through Relink and glibc, using one shared fixture.
#[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
compile_error!("the TLS access benchmark requires Linux/glibc x86_64");

#[path = "support/libraries.rs"]
#[allow(dead_code)]
mod libraries;
#[path = "support/symbols.rs"]
mod symbols;

use criterion::{BenchmarkId, Criterion, Throughput};
use elf_loader::{Linker, input::PathBuf as ElfPathBuf};
use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
use std::{
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use symbols::Symbols;

type Increment = unsafe extern "C" fn() -> u64;
const MODULE_COUNT: usize = 10;

fn main() {
    if let Ok(backend) = std::env::var("_RELINK_TLS_BACKEND") {
        let path = std::env::var_os("_RELINK_TLS_LIBRARY").expect("missing TLS fixture path");
        run_worker(&backend, Path::new(&path));
        return;
    }

    let path = build_fixture();
    println!("TLS fixture: {}", path.display());
    println!(
        "Model: x86_64 general-dynamic; {MODULE_COUNT} modules, each with an 8-byte initialized TLS block"
    );
    // Isolate registry, allocator and library state between loaders.
    for backend in ["relink", "glibc"] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(std::env::args_os().skip(1))
            .env("_RELINK_TLS_BACKEND", backend)
            .env("_RELINK_TLS_LIBRARY", &path)
            .status()
            .expect("could not start TLS benchmark worker");
        assert!(status.success(), "{backend} TLS worker failed: {status}");
    }
}

fn build_fixture() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // Rebuild once per invocation so CC/flag changes cannot reuse a stale fixture.
    let directory = root.join(format!("target/tls-bench/{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let library = directory.join("libtls-bench.so");
    let mut command = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
    command
        .args([
            "-O2",
            "-shared",
            "-fPIC",
            "-fno-lto",
            "-fno-stack-protector",
            "-nostdlib",
            "-ftls-model=global-dynamic",
            "-mtls-dialect=gnu",
            "-Wl,-z,now",
        ])
        .arg(root.join("benches/fixtures/tls.c"))
        .arg("-o")
        .arg(&library);
    eprintln!("Fixture compiler: {command:?}");
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("{command:?}: {error}"));
    assert!(status.success(), "TLS fixture compilation failed: {status}");
    for index in 1..MODULE_COUNT {
        fs::copy(&library, directory.join(format!("libtls-bench-{index}.so"))).unwrap();
    }
    library
}

fn run_worker(backend: &str, path: &Path) {
    let paths: Vec<_> = (0..MODULE_COUNT)
        .map(|index| {
            if index == 0 {
                path.to_owned()
            } else {
                path.with_file_name(format!("libtls-bench-{index}.so"))
            }
        })
        .collect();
    if backend == "glibc" {
        let libraries: Vec<_> = paths
            .iter()
            .map(|path| unsafe { Library::open(Some(path), RTLD_NOW | RTLD_LOCAL) }.unwrap())
            .collect();
        let increments: Vec<_> = libraries
            .iter()
            .map(|library| unsafe { library.symbol(c"tls_increment") })
            .collect();
        bench(backend, &increments);
    } else {
        assert_eq!(backend, "relink", "unknown TLS backend");
        let cache = libraries::LibraryCache::new(false);
        let hosts = libraries::HostLibraries::new(&cache);
        let mut context = hosts.context();
        let linker = Linker::new().with_resolver(cache.resolver());
        let loaded: Vec<_> = paths
            .iter()
            .map(|path| {
                linker
                    .run()
                    .load(&mut context, ElfPathBuf::from(path.to_str().unwrap()))
                    .expect("Relink could not load the TLS fixture")
            })
            .collect();
        let increments: Vec<_> = loaded
            .iter()
            .map(|loaded| unsafe {
                context
                    .module(loaded.root())
                    .unwrap()
                    .symbol(c"tls_increment")
            })
            .collect();
        bench(backend, &increments);
        // Every child thread has exited before the library is released.
        for loaded in loaded.into_iter().rev() {
            drop(loaded.release(&mut context).unwrap());
        }
    }
}

fn bench(backend: &str, increments: &[Increment]) {
    let increments: [Increment; MODULE_COUNT] = increments.try_into().unwrap();
    // The owner stays alive until all benchmark calls and child threads finish.
    for increment in increments {
        assert_eq!(unsafe { increment() }, 8, "wrong initial TLS template");
        thread::spawn(move || {
            assert_eq!(
                unsafe { increment() },
                8,
                "TLS must be private to each thread"
            );
            assert_eq!(unsafe { increment() }, 9);
        })
        .join()
        .unwrap();
        assert_eq!(unsafe { increment() }, 9, "child modified parent TLS");
    }

    let mut c = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(30)
        .configure_from_args();
    let mut group = c.benchmark_group("tls_access");
    group.throughput(Throughput::Elements(MODULE_COUNT as u64));
    group.bench_function(
        BenchmarkId::new(format!("hot_{MODULE_COUNT}_modules"), backend),
        |b| {
            b.iter(|| {
                for increment in increments {
                    black_box(unsafe { increment() });
                }
            });
        },
    );
    group.bench_function(
        BenchmarkId::new(format!("first_access_{MODULE_COUNT}_modules"), backend),
        |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    elapsed += thread::spawn(move || {
                        // Warm the clock without touching any fixture module's TLS.
                        black_box(Instant::now());
                        let start = Instant::now();
                        let values = increments.map(|increment| unsafe { increment() });
                        let elapsed = start.elapsed();
                        assert_eq!(values, [8; MODULE_COUNT], "new thread inherited TLS state");
                        for increment in increments {
                            assert_eq!(unsafe { increment() }, 9);
                        }
                        elapsed
                    })
                    .join()
                    .expect("TLS benchmark thread failed");
                }
                elapsed
            });
        },
    );
    group.finish();
    for increment in increments {
        let last = unsafe { increment() };
        assert_eq!(unsafe { increment() }, last.wrapping_add(1));
    }
    c.final_summary();
    println!("{backend}: TLS template, increments and thread isolation validated.");
}
