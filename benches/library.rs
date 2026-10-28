//! Linux/glibc load, teardown, and symbol lookup comparisons using real libraries.
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use elf_loader::{
    Linker, Loader,
    elf::ElfSymbolType,
    image::{Module, SymbolLookup},
    input::PathBuf,
};
use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
use std::{ffi::CString, hint::black_box, os::unix::ffi::OsStrExt, path::Path};

#[path = "support/libraries.rs"]
mod libraries;
#[path = "support/timing.rs"]
mod timing;
use libraries::{HostLibraries, LibraryCache, root_path};

// Only sample load and teardown; total would repeat the same work a third time.
const PHASES: [&str; 2] = ["load", "teardown"];

const MAX_LOOKUP_SYMBOLS: usize = 32;

const WORKLOADS: &[&str] = &[
    // Small and medium libraries with mostly C runtime dependencies.
    "libz.so.1",
    "liblz4.so.1",
    "libzstd.so.1",
    "libexpat.so.1",
    "libpcre2-8.so.0",
    "libsqlite3.so.0",
    // Real dependency chains and larger export tables.
    "libpng16.so.16",
    "libfreetype.so.6",
    // Arithmetic exports, a dependency chain, and MPFR TLS relocations.
    "libgmp.so.10",
    "libmpfr.so.6",
];

fn bench_libraries(c: &mut Criterion) {
    assert!(
        cfg!(all(target_os = "linux", target_env = "gnu")),
        "this suite requires Linux/glibc"
    );
    for soname in WORKLOADS {
        eprintln!("workload\t{soname}");
    }
    let cache = LibraryCache::new(true);
    let roots: Vec<_> = WORKLOADS
        .iter()
        .map(|&soname| (soname, root_path(&cache, soname)))
        .collect();
    // The fixed host allowlist is prepared outside timing for the entire suite.
    let hosts = HostLibraries::new(&cache);
    // Every workload must support a real native load/unload comparison.
    for (soname, path) in &roots {
        assert!(
            !native_is_loaded(path),
            "{soname} is already resident and cannot be benchmarked"
        );
        drop(unsafe { Library::open(Some(path), RTLD_NOW | RTLD_LOCAL) }.unwrap());
        assert!(
            !native_is_loaded(path),
            "{soname} remains resident after dlclose and cannot be benchmarked"
        );
    }
    // A new group keeps results separate from the old reused-context measurements.
    let mut group = c.benchmark_group("load_teardown");
    for (soname, path) in &roots {
        let linker = Linker::new()
            .with_loader(Loader::new())
            .with_resolver(cache.resolver());
        for (index, phase) in PHASES.iter().enumerate() {
            group.bench_function(format!("{soname}/relink/{phase}"), |b| {
                b.iter_custom(|iterations| {
                    timing::measure(
                        iterations,
                        || hosts.context(),
                        |context| {
                            linker
                                .run()
                                .load(context, PathBuf::from(black_box(path.to_str().unwrap())))
                                .unwrap()
                        },
                        |context, loaded| {
                            drop(loaded.release(context).unwrap());
                        },
                    )
                    .phases()[index]
                });
            });
        }
        for (index, phase) in PHASES.iter().enumerate() {
            group.bench_function(format!("{soname}/libloading/{phase}"), |b| {
                b.iter_custom(|iterations| {
                    timing::measure(
                        iterations,
                        || (),
                        |_| unsafe {
                            Library::open(Some(black_box(path)), RTLD_NOW | RTLD_LOCAL).unwrap()
                        },
                        |_, library| drop(library),
                    )
                    .phases()[index]
                });
            });
            assert!(
                !native_is_loaded(path),
                "{} became resident during measurement",
                path.display()
            );
        }
    }
    group.finish();

    let mut group = c.benchmark_group("symbol_lookup");
    for (soname, path) in &roots {
        bench_symbol_lookup(&mut group, soname, path, &cache, &hosts);
    }
    group.finish();
}

fn native_is_loaded(path: &Path) -> bool {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOLOAD | libc::RTLD_NOW) };
    if !handle.is_null() {
        unsafe { libc::dlclose(handle) };
    }
    !handle.is_null()
}

fn lookup_hit_names(module: &dyn Module) -> Vec<CString> {
    let exports = module.exports();
    let mut names = Vec::new();
    exports.for_each(&mut |symbol| {
        if symbol.is_exported()
            && matches!(
                symbol.symbol_type(),
                ElfSymbolType::FUNC | ElfSymbolType::OBJECT
            )
        {
            names.push(exports.symbol_name(symbol).unwrap().to_owned());
        }
    });
    names.sort_unstable();
    names.dedup();
    // Select the unversioned API's actual definition; omit TLS and IFUNCs.
    names.retain(|name| {
        exports
            .lookup(&mut SymbolLookup::new(name.to_bytes()))
            .is_some_and(|symbol| {
                matches!(
                    symbol.symbol_type(),
                    ElfSymbolType::FUNC | ElfSymbolType::OBJECT
                )
            })
    });
    assert!(!names.is_empty(), "no ordinary root exports to benchmark");
    let count = names.len().min(MAX_LOOKUP_SYMBOLS);
    // Spread the working set across the sorted export names deterministically.
    (0..count)
        .map(|index| names[index * names.len() / count].clone())
        .collect()
}

fn bench_symbol_lookup(
    group: &mut BenchmarkGroup<'_, WallTime>,
    soname: &str,
    path: &Path,
    cache: &LibraryCache,
    hosts: &HostLibraries,
) {
    let mut context = hosts.context();
    let loaded = Linker::new()
        .with_resolver(cache.resolver())
        .run()
        .load(&mut context, PathBuf::from(path.to_str().unwrap()))
        .unwrap();
    let module = context.module(loaded.root()).unwrap();
    let native = unsafe { Library::open(Some(path), RTLD_NOW | RTLD_LOCAL) }.unwrap();
    let hits = lookup_hit_names(module);
    let misses: Vec<_> = (0..hits.len())
        .map(|index| CString::new(format!("__relink_bench_missing_symbol_{index}__")).unwrap())
        .collect();
    eprintln!("lookup\t{soname}\t{} names per case", hits.len());

    for (case, names, found) in [("hit", &hits, true), ("miss", &misses, false)] {
        // Validate both outcomes before timing, including the generated misses.
        // SAFETY: symbols are inspected only as opaque addresses, never called or dereferenced.
        for name in names {
            assert_eq!(
                unsafe { module.get::<*const ()>(name.to_bytes()) }
                    .unwrap()
                    .is_some(),
                found,
                "unexpected Relink lookup result for {name:?}"
            );
            assert_eq!(
                unsafe { native.get::<*const ()>(name.to_bytes_with_nul()) }.is_ok(),
                found,
                "unexpected native lookup result for {name:?}"
            );
        }
        group.bench_function(format!("{soname}/relink/{case}"), |b| {
            let mut names = names.iter().cycle();
            b.iter(|| {
                let name = black_box(names.next().unwrap());
                // SAFETY: retain only an opaque address while the module stays loaded.
                unsafe { black_box(module).get::<*const ()>(name.to_bytes()) }
            });
        });
        group.bench_function(format!("{soname}/libloading/{case}"), |b| {
            let mut names = names.iter().cycle();
            b.iter(|| {
                let name = black_box(names.next().unwrap());
                // SAFETY: retain only an opaque address while the library stays loaded.
                unsafe { black_box(&native).get::<*const ()>(name.to_bytes_with_nul()) }
            });
        });
    }
    drop(native);
    drop(loaded.release(&mut context).unwrap());
}

criterion_group!(benches, bench_libraries);
criterion_main!(benches);
