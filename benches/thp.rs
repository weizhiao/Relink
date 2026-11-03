//! Clang frontend and LLVM backend execution with and without Relink THP.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("the THP application benchmark requires Linux/glibc");

#[path = "support/clang.rs"]
mod clang;
#[path = "support/libraries.rs"]
#[allow(dead_code)]
mod libraries;
#[path = "support/llvm.rs"]
mod llvm;
#[path = "support/mappings.rs"]
mod mappings;
#[path = "support/symbols.rs"]
mod symbols;

use crate::{
    libraries::{HostLibraries, LibraryCache},
    symbols::Symbols,
};
use criterion::{BatchSize, BenchmarkId, Criterion};
use elf_loader::{
    Linker, Loader,
    input::Path,
    os::{DefaultMmap, Mmap, ThpPolicy},
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

#[derive(Clone, Copy)]
enum Workload {
    Clang,
    Llvm,
}

impl Workload {
    fn from_env() -> Self {
        match std::env::var("THP_WORKLOAD").as_deref().unwrap_or("clang") {
            "clang" => Self::Clang,
            "llvm" => Self::Llvm,
            other => panic!("unknown THP_WORKLOAD {other}; choose clang or llvm"),
        }
    }
}

fn main() {
    let workload = Workload::from_env();
    match std::env::var("_RELINK_THP_BACKEND") {
        Ok(backend) => {
            let library = std::env::var_os("_RELINK_THP_LIBRARY")
                .expect("benchmark parent must provide the selected library");
            run_worker(workload, &backend, FsPath::new(&library));
        }
        Err(_) => run_all(workload),
    }
}

fn run_all(workload: Workload) {
    let library = match workload {
        Workload::Clang => clang::library_path(),
        Workload::Llvm => llvm::library_path(),
    };
    println!("THP application benchmark");
    println!("Library: {}", library.display());
    match workload {
        Workload::Clang => {
            println!("Workload: simdjson 3.12.3 C++17 parse/type-check");
            println!("Input: {}", clang::input_path().display());
            println!("Timing: parsing; loading, collapse and AST validation are excluded.");
        }
        Workload::Llvm => {
            println!("Workload: simdjson 3.12.3 LLVM O3 optimization + native object generation");
            println!("Input: {}", llvm::input_path().display());
            println!(
                "Timing: optimization/codegen; loading, IR setup, verification and teardown are excluded."
            );
        }
    }
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
    println!("Default loaders may already use THP; inspect actual page counts.");
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
            match DefaultMmap::new().thp_page_size() {
                Some(size) => eprintln!("THP page size: {} MiB", size.bytes() / (1024 * 1024)),
                None => eprintln!("THP size unavailable; THP optimization skipped"),
            }
            Loader::new().with_thp(ThpPolicy::Collapse)
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
            Workload::Llvm => 10,
        })
        .configure_from_args();
    match workload {
        Workload::Clang => bench_clang(&mut c, backend, library, path),
        Workload::Llvm => bench_llvm(&mut c, backend, library, path),
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

fn bench_llvm(c: &mut Criterion, backend: &str, library: &(impl Symbols + ?Sized), path: &FsPath) {
    let llvm = llvm::Llvm::new(library);
    let expected = {
        let mut compilation = llvm.prepare();
        compilation.run();
        compilation.fingerprint()
    };
    eprintln!("workload_result\t{expected}");
    let before = mappings::snapshot(path, "LLVMRunPasses", llvm.anchor());
    let mut group = c.benchmark_group("thp_llvm");
    group.bench_function(BenchmarkId::new("simdjson_o3_codegen", backend), |b| {
        b.iter_batched_ref(
            || llvm.prepare(),
            |compilation| compilation.run(),
            BatchSize::PerIteration,
        );
    });
    let mut compilation = llvm.prepare();
    compilation.run();
    assert_eq!(compilation.fingerprint(), expected);
    group.finish();
    mappings::report(
        "libLLVM",
        before,
        mappings::snapshot(path, "LLVMRunPasses", llvm.anchor()),
    );
}
