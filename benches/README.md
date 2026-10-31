# Performance benchmarks

The `library` suite requires Linux/glibc and libraries listed in `/etc/ld.so.cache`.

## THP application execution

```sh
cargo bench --bench thp --features version
# Use the same available CPU for all three cases:
taskset -c 0 cargo bench --bench thp --features version
```

Requires Linux/glibc and `python3` with a matching shared `libpython` and standard
library (Python 3.10+). The benchmark discovers the installed library and compares
exactly three ways of loading it:

| Case | Loader |
|---|---|
| `relink` | `Loader::new()` |
| `relink_thp` | `Loader::new().with_thp(...)`, using the kernel's PMD page size |
| `glibc` | `libloading` / glibc `dlopen(RTLD_NOW \| RTLD_LOCAL)` |

All three execute the same tasks in `workloads/python.py`:

- **`stdlib_compile`:** compile nine real standard-library source files into
  bytecode, without executing the modules or writing `.pyc` files.
- **`json_roundtrip`:** decode and re-encode a JSON source-index document built
  from those files and their metadata.

Only task execution and its result check are timed. Loading, interpreter startup,
source-file I/O, preparation, warmup, and finalization are outside timing. Each
loader runs in a fresh process with a fixed Python hash seed and no `site`
customizations. Library paths, Python versions, input sizes, JSON accelerators,
and result checksums are printed to make the cases comparable.

Defaults are 1 s warmup, 5 s measurement, and 30 samples. Criterion options and
workload filters are forwarded to all three workers, and results are written to
`target/criterion/thp_python/`. For example, append `-- stdlib_compile` to run
only compilation. `ci/bench.sh` continues to run the separate library suite.

This compares the loaders' own behavior: the harness does not force base pages,
force THP promotion, change system policy, or rewrite/copy the library. The THP
configuration is a request; whether the kernel supplies huge pages still depends
on its policy and mapping state. Timings alone do not prove huge-page backing.

## Fixed workloads

Criterion uses this compiled-in suite, with no workload argument or environment
override. The profiling runner accepts `--workload` separately:

| Coverage | Libraries |
|---|---|
| Small and medium compression libraries | `libz.so.1`, `liblz4.so.1`, `libzstd.so.1` |
| Parser, regular expressions and database | `libexpat.so.1`, `libpcre2-8.so.0`, `libsqlite3.so.0` |
| Image/font dependency chains | `libpng16.so.16`, `libfreetype.so.6` |
| Arithmetic exports, dependency chain and TLS relocations | `libgmp.so.10`, `libmpfr.so.6` |

All libraries are required and must unload after `dlclose`; preflight rejects
resident roots before sampling. CI installs their runtime packages; the run
records resolved library paths and file hashes for reproducible comparisons.

## CI comparison

Compare Relink with `libloading` (`RTLD_NOW | RTLD_LOCAL`):

```sh
bash ci/bench.sh
bash ci/bench.sh --save-baseline before
bash ci/bench.sh --baseline before
```

The suite measures load, teardown, and symbol lookup (hit/miss). Total has no
separate sampling pass. Each case defaults to 1 s warmup, 2 s measurement and
30 samples. Override with
`RELINK_BENCH_WARMUP`, `RELINK_BENCH_DURATION` and `RELINK_BENCH_SAMPLES`.
Criterion options are forwarded; avoid `--quiet` or filters that omit cases.
Reports go to `target/benchmark-report/`, raw data to `target/criterion/`.

To run only symbol lookup without generating the combined CI report:

```sh
cargo bench --bench library --features version -- symbol_lookup
```

## Symbol lookup

The `symbol_lookup` group compares Relink's `Module::get` with
`libloading::Library::get` on already loaded libraries:

- **Hit:** cycle through up to 32 names sampled evenly from sorted root exports.
- **Miss:** cycle through the same number of generated absent names.

Both outcomes are checked before timing. Names, library loading, context lookup,
and unloading are outside timing; each measured iteration performs one lookup.
Native names include a prepared NUL terminator. TLS and IFUNCs are excluded, and
symbol addresses are never called or dereferenced. The report uses ns per lookup.

These measure public API costs: Relink searches root exports, while native
`dlsym` can search dependencies. Native misses also construct and drop a
`libloading` error; Relink returns `Ok(None)`.

## Relink profiling

```sh
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release --example load_bench --features version
target/release/examples/load_bench --workload libsqlite3.so.0
perf record -e cpu-clock -F 999 --call-graph dwarf -- \
  target/release/examples/load_bench --workload libsqlite3.so.0 \
  --iterations 1000 --rounds 1
perf report
```

Defaults: `--warmup-ms 1000 --sample-ms 1000 --rounds 9`; `--iterations N`
overrides calibration. Output includes average `load_ns`, `teardown_ns` and
`total_ns` per iteration, plus P10/median/P90 across round averages.

## Load and teardown timing

Every Relink iteration uses a fresh context with fixed host runtimes:

- **Load:** library/dependency loading, relocation and constructors.
- **Teardown:** release and destruction of released modules, including finalizers and unmapping.

Context creation/destruction, host imports and cache setup are excluded. The profiling runner
also reports total as load + teardown from the same iteration, without extra sampling.

These are warm-file-cache measurements. Native timing uses `dlopen`/`dlclose`;
its namespace persists and dependencies may remain resident. Roots retained by
`NODELETE` or GNU-unique bindings are unsuitable for this suite. Relink measures
release; any modules retained until context destruction are cleaned up outside timing.

Criterion samples load and teardown independently. `perf` also captures preparation
outside timed regions.
Compare on an idle machine with the same CPU affinity. Regenerate baselines after
harness changes, including the exclusion of context destruction from teardown; the current `load_teardown` group differs from old `load_unload` results.
