# Performance benchmarks

Requires Linux/glibc. Use a fixed CPU affinity on an idle machine and regenerate
baselines after harness changes.

## THP execution

Requires a shared libclang and a preprocessed simdjson 3.12.3 input. Use matching
Clang/libclang versions (18.1.x was used in the selection experiment).

```sh
CLANGXX=clang++-18 python3 benches/workloads/prepare_simdjson.py
export LIBCLANG_LIBRARY=/path/to/libclang.so
# Replace 0 with an available CPU.
taskset -c 0 cargo bench --bench thp --features std,version
cargo bench --bench thp --features std,version -- --test  # functional check
```

| Case | Loader |
|---|---|
| `relink` | Default Relink |
| `relink_thp` | Relink with synchronous `ThpPolicy::Collapse`, using the kernel's PMD size |
| `glibc` | `libloading` with `RTLD_NOW \| RTLD_LOCAL` |

Each case runs in a separate process, parsing and type-checking the same
[preprocessed simdjson.cpp](workloads/README.md) through
`clang_parseTranslationUnit2`, including function bodies. The parse call and its
status check are timed, including warm-cache input reads. Library loading,
collapse, index creation, diagnostic checks, AST traversal, and translation-unit
teardown are excluded. This measures compiler frontend work, not JSON parsing.
The input defaults to `target/thp-input/simdjson.ii`; override with `SIMDJSON_INPUT`.

Defaults: 1 s warmup, 5 s measurement, 30 samples. Criterion options are forwarded
to all workers; results go to `target/criterion/thp_clang/`. Output groups timings
and before/after libclang huge-page counts by case, then checks that all
AST node counts and cursor-kind hashes match. Error diagnostics fail validation.
These are structural sanity checks, not semantic-equivalence proofs. Compare
runs using the same libclang and input.

The huge-page table reports MiB from `/proc/self/smaps`: `FilePmdMapped`,
`AnonHugePages`, and `ShmemPmdMapped`. `Partial VMAs` overlap the image boundary
and are excluded from counts. Zero counts with no partial VMAs mean no PMD huge
pages were observed at those snapshots; dependencies and Clang's heap are excluded.

Collapse failures do not abort loading. Check actual page counts: default loaders
may also use THP, and collapse changes alignment as well as page backing. Separate
processes still share the file cache, so timings alone do not isolate THP gains.

## Library comparison

```sh
bash ci/bench.sh
bash ci/bench.sh --save-baseline before
bash ci/bench.sh --baseline before
# Symbol lookup only, without the combined CI report:
cargo bench --bench library --features version -- symbol_lookup
```

The fixed suite compares Relink with `libloading` (`RTLD_NOW | RTLD_LOCAL`).
All libraries below must be available through `/etc/ld.so.cache` and unload after
`dlclose`; preflight rejects resident roots. CI installs the runtime packages
and records resolved paths and hashes.

| Coverage | Libraries |
|---|---|
| Compression | `libz.so.1`, `liblz4.so.1`, `libzstd.so.1` |
| Parsing and database | `libexpat.so.1`, `libpcre2-8.so.0`, `libsqlite3.so.0` |
| Images and fonts | `libpng16.so.16`, `libfreetype.so.6` |
| Arithmetic and TLS | `libgmp.so.10`, `libmpfr.so.6` |

Defaults: 1 s warmup, 2 s measurement, 30 samples. Override with
`RELINK_BENCH_WARMUP`, `RELINK_BENCH_DURATION`, and `RELINK_BENCH_SAMPLES`.
Criterion options are forwarded; avoid `--quiet` or filters that omit cases when
using `ci/bench.sh`. Reports go to `target/benchmark-report/`, raw data to
`target/criterion/`. This suite has no workload selector.

- **Load:** library/dependency loading, relocation, and constructors.
- **Teardown:** module release, finalizers, and unmapping. Relink context setup
  and destruction, host imports, and cache setup are outside timing.
- **Lookup:** one hit or miss per iteration on loaded libraries, reported in ns.
  Hits sample up to 32 root exports; misses use absent names. TLS and IFUNCs are
  excluded, and outcomes are checked before timing.

These are warm-file-cache measurements. Native dependencies may remain resident;
Relink modules retained until context destruction are cleaned up outside timing.
Lookup measures public API costs: Relink searches root exports, while `dlsym`
can search dependencies and native misses construct a `libloading` error.
Criterion samples load and teardown independently; total has no separate pass.
Old `load_unload` baselines are incompatible with the current `load_teardown` group.

## Relink profiling

```sh
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release --example load_bench --features version
target/release/examples/load_bench --workload libsqlite3.so.0
perf record -e cpu-clock -F 999 --call-graph dwarf -- \
  target/release/examples/load_bench --workload libsqlite3.so.0 \
  --iterations 1000 --rounds 1
perf report
```

The profiling runner accepts `--workload`. Defaults are `--warmup-ms 1000`,
`--sample-ms 1000`, and `--rounds 9`; `--iterations N` overrides calibration. Output
includes average load, teardown, and their sum in ns per iteration, plus
P10/median/P90 across round averages. `perf` also captures preparation outside
timed regions.
