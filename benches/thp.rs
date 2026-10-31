//! Application execution with and without Relink's file-backed THP policy.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("the THP application benchmark requires Linux/glibc");

#[path = "support/libraries.rs"]
#[allow(dead_code)]
mod libraries;
#[path = "support/mappings.rs"]
mod mappings;
#[path = "support/python.rs"]
mod python;

use crate::{
    libraries::{HostLibraries, LibraryCache},
    python::{Installation, Python, Symbols},
};
use criterion::{BenchmarkId, Criterion};
use elf_loader::{Linker, Loader, input::Path, os::PageSize};
use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
use std::{hint::black_box, os::unix::ffi::OsStrExt, process::Command, time::Duration};

fn main() {
    let Ok(backend) = std::env::var("_RELINK_THP_BACKEND") else {
        // Isolate CPython's process-global state between the three loaders.
        for backend in ["relink", "relink_thp", "glibc"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(std::env::args_os().skip(1))
                .env("_RELINK_THP_BACKEND", backend)
                .env("PYTHONHASHSEED", "0")
                .env_remove("PYTHONPATH")
                .env_remove("PYTHONHOME")
                .status()
                .unwrap();
            assert!(status.success(), "{backend} worker failed: {status}");
        }
        return;
    };
    let installation = Installation::discover();
    eprintln!("python_library\t{}", installation.library.display());
    let mut c = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(30)
        .configure_from_args();

    if backend == "glibc" {
        let library = unsafe { Library::open(Some(&installation.library), RTLD_NOW | RTLD_LOCAL) }
            .expect("glibc could not load libpython");
        bench(&mut c, &backend, &library, &installation);
    } else {
        assert!(matches!(backend.as_str(), "relink" | "relink_thp"));
        let cache = LibraryCache::new(false);
        let hosts = HostLibraries::new(&cache);
        let mut context = hosts.context();
        let loader = if backend == "relink_thp" {
            let size =
                std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size")
                    .expect("kernel does not expose its THP PMD size");
            Loader::new().with_thp(PageSize::new(size.trim().parse().unwrap()).unwrap())
        } else {
            Loader::new()
        };
        let loaded = Linker::new()
            .with_loader(loader)
            .with_resolver(cache.resolver())
            .run()
            .load(
                &mut context,
                Path::new(installation.library.as_os_str().as_bytes()).into(),
            )
            .unwrap();
        bench(
            &mut c,
            &backend,
            context.module(loaded.root()).unwrap(),
            &installation,
        );
        drop(loaded.release(&mut context).unwrap());
    }
    c.final_summary();
}

fn bench(
    c: &mut Criterion,
    backend: &str,
    library: &(impl Symbols + ?Sized),
    installation: &Installation,
) {
    let python = Python::new(library, installation);
    let mut group = c.benchmark_group("thp_python");
    for name in [c"stdlib_compile", c"json_roundtrip"] {
        let function = python.function(name);
        let expected = python.run(function);
        eprintln!(
            "python_result\t{backend}\t{}\t{expected}",
            name.to_str().unwrap()
        );
        // Loading, interpreter initialization, input I/O and teardown are outside timing.
        group.bench_function(BenchmarkId::new(name.to_str().unwrap(), backend), |b| {
            b.iter(|| assert_eq!(black_box(python.run(black_box(function))), expected));
        });
    }
    group.finish();
    // Snapshot actual backing while this interpreter and its module are alive.
    // Reading smaps and the ELF file happens after all timed workloads.
    mappings::report(backend, library, installation);
}
