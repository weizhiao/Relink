//! Clang parsing with and without Relink's file-backed THP policy.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("the THP application benchmark requires Linux/glibc");

#[path = "support/clang.rs"]
mod clang;
#[path = "support/libraries.rs"]
#[allow(dead_code)]
mod libraries;
#[path = "support/mappings.rs"]
mod mappings;

use crate::{
    clang::{Clang, Symbols},
    libraries::{HostLibraries, LibraryCache},
};
use criterion::{BatchSize, BenchmarkId, Criterion};
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
    path::Path as FsPath,
    process::Command,
    time::Duration,
};

fn main() {
    match std::env::var("_RELINK_THP_BACKEND") {
        Ok(backend) => run_worker(&backend, &clang::library_path()),
        Err(_) => run_all(),
    }
}

fn run_all() {
    let library = clang::library_path();
    println!("Clang THP benchmark");
    println!("Library: {}", library.display());
    println!("Workload: simdjson 3.12.3 simdjson.cpp, C++17 parse/type-check");
    println!("Input: {}", clang::input_path().display());
    println!("Timing: Clang parsing only; loading and synchronous collapse are excluded.");
    let mut expected = None;

    // Clang and its C++ dependencies have process-global state. Each case runs
    // in a separate process using the same library, input, and Criterion options.
    for (backend, label) in [
        ("relink", "Relink / system THP policy"),
        ("relink_thp", "Relink / synchronous MADV_COLLAPSE"),
        ("glibc", "glibc / system THP policy"),
    ] {
        println!("\n=== {label} ===");
        println!("Running…");
        io::stdout().flush().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(std::env::args_os().skip(1))
            .env("_RELINK_THP_BACKEND", backend)
            .env("LIBCLANG_LIBRARY", &library)
            .output()
            .expect("could not start benchmark worker");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Keep diagnostics on failure. Successful cases show metadata and page
        // snapshots first, then Criterion's timings and confidence intervals.
        if !output.status.success() {
            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
            panic!("{backend} worker failed: {}", output.status);
        }
        let mut result = None;
        for line in stderr.lines() {
            if let Some(value) = line.strip_prefix("clang_result\t") {
                result = Some(value);
            } else if !line.starts_with("Benchmarking ") {
                println!("{line}");
            }
        }
        let result = result.expect("worker did not report its AST fingerprint");
        if let Some(expected) = &expected {
            assert_eq!(result, expected, "Clang output differs between loaders");
        } else {
            expected = Some(result.to_owned());
        }
        io::stdout().write_all(&output.stdout).unwrap();
    }
    println!("\nValidation: all three loaders produced identical AST fingerprints.");
    println!("Fingerprint: {}", expected.unwrap());
    println!(
        "Pages cover libclang only. Zero counts with no partial VMAs mean no observed PMD huge pages."
    );
    println!(
        "System-policy cases may also use THP; layout and shared file-cache effects are not isolated."
    );
}

fn run_worker(backend: &str, library_path: &FsPath) {
    if backend == "glibc" {
        let library = unsafe { Library::open(Some(library_path), RTLD_NOW | RTLD_LOCAL) }
            .expect("glibc could not load libclang");
        bench(backend, &library, library_path);
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
        .expect("Relink could not load libclang");
    bench(
        backend,
        context.module(loaded.root()).unwrap(),
        library_path,
    );
    drop(loaded.release(&mut context).unwrap());
}

fn bench(backend: &str, library: &(impl Symbols + ?Sized), library_path: &FsPath) {
    let clang = Clang::new(library);
    // Validate the full parse before timing; diagnostics and AST traversal are untimed.
    let expected = clang.parse().fingerprint();
    eprintln!("clang_result\t{expected}");
    let before = mappings::snapshot(library_path, clang.anchor());

    let mut c = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(30)
        .configure_from_args();
    let mut group = c.benchmark_group("thp_clang");
    group.bench_function(BenchmarkId::new("simdjson_parse", backend), |b| {
        // The translation unit is dropped after timing. Each parse is fresh;
        // PerIteration avoids retaining batches of large ASTs.
        b.iter_batched_ref(
            || None,
            |unit| *unit = Some(black_box(&clang).parse()),
            BatchSize::PerIteration,
        );
    });
    assert_eq!(clang.parse().fingerprint(), expected);
    group.finish();
    let after = mappings::snapshot(library_path, clang.anchor());
    mappings::report(before, after);
    c.final_summary();
}
