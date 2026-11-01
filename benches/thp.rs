//! Clang frontend and NPB CG execution with and without Relink THP.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("the THP application benchmark requires Linux/glibc");

#[path = "support/cg.rs"]
mod cg;
#[path = "support/clang.rs"]
mod clang;
#[path = "support/libraries.rs"]
#[allow(dead_code)]
mod libraries;
#[path = "support/mappings.rs"]
mod mappings;
#[path = "support/symbols.rs"]
mod symbols;

use crate::{
    libraries::{HostLibraries, LibraryCache},
    symbols::Symbols,
};
use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode};
use elf_loader::{
    Linker, Loader,
    input::Path,
    os::{PageSize, ThpPolicy},
};
use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
use std::{
    hint::black_box,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path as FsPath, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum Workload {
    Clang,
    Cg,
}

impl Workload {
    fn from_env() -> Self {
        match std::env::var("THP_WORKLOAD").as_deref().unwrap_or("clang") {
            "clang" => Self::Clang,
            "cg" => Self::Cg,
            other => panic!("unknown THP_WORKLOAD {other}; choose clang or cg"),
        }
    }
    fn library_path(self) -> PathBuf {
        match self {
            Self::Clang => clang::library_path(),
            Self::Cg => cg::library_path(),
        }
    }
}

fn main() {
    let workload = Workload::from_env();
    match std::env::var("_RELINK_THP_BACKEND") {
        Ok(backend) => {
            configure_process_thp();
            let library = std::env::var_os("_RELINK_THP_LIBRARY")
                .expect("benchmark parent must provide the selected library");
            run_worker(workload, &backend, FsPath::new(&library));
        }
        Err(_) => run_all(workload),
    }
}

fn configure_process_thp() {
    match std::env::var("THP_EXCEPT_ADVISED").as_deref() {
        Err(_) | Ok("0") => eprintln!("Process THP: system policy"),
        Ok("1") => {
            // Linux PR_THP_DISABLE_EXCEPT_ADVISED = 1 << 1. This affects only
            // this worker; fail explicitly if the kernel does not support it.
            let result =
                unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1usize, 2usize, 0usize, 0usize) };
            assert_eq!(
                result,
                0,
                "THP except-advised is unavailable: {}",
                io::Error::last_os_error()
            );
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_THP_DISABLE, 0usize, 0usize, 0usize, 0usize) },
                3
            );
            eprintln!("Process THP: except-advised (global policy unchanged)");
        }
        Ok(value) => panic!("THP_EXCEPT_ADVISED must be 0 or 1, got {value}"),
    }
}

fn run_all(workload: Workload) {
    let library = workload.library_path();
    println!("THP application benchmark");
    println!("Library: {}", library.display());
    match workload {
        Workload::Clang => {
            println!("Workload: simdjson 3.12.3 C++17 parse/type-check");
            println!("Input: {}", clang::input_path().display());
            println!("Timing: parsing; loading, collapse and AST validation are excluded.");
        }
        Workload::Cg => {
            println!("Workload: serial NPB CG, static sparse-matrix workspace in BSS");
            println!("Timing: original NPB kernel; setup and numerical verification are excluded.");
        }
    };
    let mut expected = None;
    // Isolate process-global library state; all cases use identical inputs/options.
    for (backend, label) in [
        ("relink", "Relink / system THP policy"),
        ("relink_thp", "Relink / file Collapse + BSS Advise"),
        ("glibc", "glibc / system THP policy"),
    ] {
        println!("\n=== {label} ===\nRunning…");
        io::stdout().flush().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(std::env::args_os().skip(1))
            .env("_RELINK_THP_BACKEND", backend)
            .env("_RELINK_THP_LIBRARY", &library)
            .output()
            .expect("could not start benchmark worker");
        if !output.status.success() {
            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
            panic!("{backend} worker failed: {}", output.status);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut result = None;
        for line in stderr.lines() {
            if let Some(value) = line.strip_prefix("workload_result\t") {
                result = Some(value);
            } else if !line.starts_with("Benchmarking ") {
                println!("{line}");
            }
        }
        let result = result.expect("worker did not report a validated workload result");
        if let Some(expected) = &expected {
            assert_eq!(result, expected, "workload output differs between loaders");
        } else {
            expected = Some(result.to_owned());
        }
        io::stdout().write_all(&output.stdout).unwrap();
    }
    println!("\nValidation: all three loaders produced matching results.");
    println!("Result: {}", expected.unwrap());
    println!("Pages cover the root library, including BSS; dependencies and heap are excluded.");
    println!("Default loaders may already use THP; inspect page counts and the process policy.");
}

fn run_worker(workload: Workload, backend: &str, library_path: &FsPath) {
    if backend == "glibc" {
        let library = unsafe { Library::open(Some(library_path), RTLD_NOW | RTLD_LOCAL) }
            .expect("glibc could not load the workload library");
        bench(workload, backend, &library, library_path);
        return;
    }
    let loader = match backend {
        "relink" => Loader::new(),
        "relink_thp" => {
            let size =
                std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size")
                    .expect("kernel does not expose its THP PMD size");
            let size = PageSize::new(size.trim().parse().expect("invalid THP PMD size"))
                .expect("THP PMD size must be a power of two");
            eprintln!(
                "Requested huge-page size: {} MiB",
                size.bytes() / (1024 * 1024)
            );
            Loader::new().with_thp(ThpPolicy::Collapse(size))
        }
        _ => panic!("unknown benchmark backend: {backend}"),
    };
    let cache = LibraryCache::new(false);
    let hosts = HostLibraries::new(&cache);
    let mut context = hosts.context();
    let loaded = Linker::new()
        .with_loader(loader)
        .with_resolver(cache.resolver())
        .run()
        .load(
            &mut context,
            Path::new(library_path.as_os_str().as_bytes()).into(),
        )
        .expect("Relink could not load the workload library");
    bench(
        workload,
        backend,
        context.module(loaded.root()).unwrap(),
        library_path,
    );
    drop(loaded.release(&mut context).unwrap());
}

fn bench(workload: Workload, backend: &str, library: &(impl Symbols + ?Sized), path: &FsPath) {
    let mut c = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(match workload {
            Workload::Clang => 30,
            Workload::Cg => 10,
        })
        .configure_from_args();
    match workload {
        Workload::Clang => bench_clang(&mut c, backend, library, path),
        Workload::Cg => bench_cg(&mut c, backend, library, path),
    }
    c.final_summary();
}

fn bench_clang(c: &mut Criterion, backend: &str, library: &(impl Symbols + ?Sized), path: &FsPath) {
    let clang = clang::Clang::new(library);
    let expected = clang.parse().fingerprint();
    eprintln!("workload_result\t{expected}");
    let before = mappings::snapshot(path, "clang_parseTranslationUnit2", clang.anchor());
    let mut group = c.benchmark_group("thp_clang");
    group.bench_function(BenchmarkId::new("simdjson_parse", backend), |b| {
        // Teardown is untimed; PerIteration avoids retaining batches of large ASTs.
        b.iter_batched_ref(
            || None,
            |unit| *unit = Some(black_box(&clang).parse()),
            BatchSize::PerIteration,
        );
    });
    assert_eq!(clang.parse().fingerprint(), expected);
    group.finish();
    mappings::report(
        "libclang",
        before,
        mappings::snapshot(path, "clang_parseTranslationUnit2", clang.anchor()),
    );
}

fn bench_cg(c: &mut Criterion, backend: &str, library: &(impl Symbols + ?Sized), path: &FsPath) {
    let mut cg = cg::Cg::new(library);
    let start = Instant::now();
    let (kernel, expected) = cg.run();
    eprintln!(
        "Initial NPB run: kernel {:.6} s, application {:.6} s (includes setup/verification)",
        kernel.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );
    eprintln!("workload_result\t{expected}");
    let before = mappings::snapshot(path, "relink_cg_run", cg.anchor());
    let mut group = c.benchmark_group("thp_cg");
    group.sampling_mode(SamplingMode::Flat);
    let class = expected
        .split('\t')
        .next()
        .unwrap()
        .trim_start_matches("class=");
    group.bench_function(BenchmarkId::new(format!("class_{class}"), backend), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let (kernel, result) = cg.run();
                assert_eq!(result, expected, "NPB CG result changed between iterations");
                elapsed += kernel;
            }
            elapsed
        });
    });
    group.finish();
    mappings::report(
        "NPB CG",
        before,
        mappings::snapshot(path, "relink_cg_run", cg.anchor()),
    );
}
