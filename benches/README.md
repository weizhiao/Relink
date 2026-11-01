# Performance benchmarks

Requires Linux/glibc. Use a fixed CPU affinity on an idle machine and regenerate
baselines after harness changes.

## THP execution

Choose `THP_WORKLOAD=clang` (the default) or `THP_WORKLOAD=cg`. Both compare
Relink, Relink with THP, and glibc in separate processes.

Clang requires `llvm-config` on `PATH`, a shared libclang and preprocessed simdjson
3.12.3 input. Use matching
Clang/libclang versions (18.1.x was used in the selection experiment).

```sh
python3 benches/workloads/prepare.py simdjson
# Replace 0 with an available CPU.
taskset -c 0 cargo bench --bench thp --features std,version
cargo bench --bench thp --features std,version -- --test  # functional check
```

Preparation uses the system `clang++` by default; set `CLANGXX` to override it.
The benchmark automatically finds native libclang in `llvm-config --libdir`.
It prefers an unversioned
`libclang.so` when available, otherwise the highest installed major version.
All three workers use the same selected file, printed at startup.

CG uses the serial NAS Parallel Benchmarks conjugate-gradient workload, whose
large static sparse-matrix arrays exercise anonymous BSS:

```sh
python3 benches/workloads/prepare.py cg  # Class B, about 427 MiB of BSS
THP_WORKLOAD=cg taskset -c 0 cargo bench --bench thp --features std,version
# Controlled anonymous-THP comparison; affects benchmark workers only:
THP_WORKLOAD=cg THP_EXCEPT_ADVISED=1 taskset -c 0 \
  cargo bench --bench thp --features std,version
# Faster functional check with the smaller Class A:
python3 benches/workloads/prepare.py cg --class A
THP_WORKLOAD=cg NPB_CG_LIBRARY=target/thp-input/npb-cg/libnpb-cg-A.so \
  cargo bench --bench thp --features std,version -- --test
```

`NPB_CG_LIBRARY` overrides the default `target/thp-input/npb-cg/libnpb-cg-B.so`.
Preparation requires Python 3, a C compiler (`CC`, default `cc`), and network access
on the first run. The benchmark itself performs no downloads or compilation of inputs.

| Case | Loader |
|---|---|
| `relink` | Default Relink |
| `relink_thp` | Relink with file `Collapse` and BSS `Advise`, using the kernel's PMD size |
| `glibc` | `libloading` with `RTLD_NOW \| RTLD_LOCAL` |

For Clang, each case parses and type-checks the same
[preprocessed simdjson.cpp](workloads/README.md) through
`clang_parseTranslationUnit2`, including function bodies. The parse call and its
status check are timed, including warm-cache input reads. Library loading,
collapse, index creation, diagnostic checks, AST traversal, and translation-unit
teardown are excluded. This measures compiler frontend work, not JSON parsing.
The input defaults to `target/thp-input/simdjson.ii`; override with `SIMDJSON_INPUT`.

CG preserves the original matrix setup, warmup, 15 (Class A) or 75 (Class B)
inverse-power iterations, and numerical verification. The adapter suppresses
progress printing and records the original kernel interval with a monotonic
clock. Criterion measures this interval; matrix setup and verification are
excluded. Every repetition reinitializes the matrix in the same resident BSS,
checks NPB verification, and compares the final eigenvalue across repetitions
and loaders. The initial run also reports kernel and whole-application time,
including initialization and verification; library loading is excluded from both.

Defaults: 1 s warmup, 5 s measurement; Clang uses 30 samples, CG uses 10 with flat
sampling. Class B can take roughly 15–25 s per repetition on a fast machine,
so a full three-loader run takes several minutes even with a short measurement
time. Use Class A for quick checks. Criterion options are forwarded to all workers;
results go to `target/criterion/thp_clang/` or `target/criterion/thp_cg/`. Output groups timings
and before/after huge-page counts by case, then checks that all
AST node counts and cursor-kind hashes match for Clang. Error diagnostics fail validation.
These are structural sanity checks, not semantic-equivalence proofs. Compare
runs using the same libclang and input.

The mapping table reports MiB from `/proc/self/smaps`: `FilePmdMapped`,
`AnonHugePages`, `ShmemPmdMapped`, and RSS. `Partial VMAs` overlap the image boundary
and are excluded from counts. Zero counts with no partial VMAs mean no PMD huge
pages were observed at those snapshots. Counts cover the selected root library,
including its BSS; dependencies and heap allocations are excluded. Both snapshots
follow the initial validation run, so CG's BSS has already been initialized.

Collapse failures do not abort loading. Check actual page counts: default loaders
may also use THP. THP policies choose an ELF-compatible load bias that maximizes
executable coverage, then total read-only coverage; they can change alignment as
well as page backing. Separate processes still share the file cache, so timings
alone do not isolate THP gains.

`THP_EXCEPT_ADVISED=1` sets Linux's process-local
[`PR_THP_DISABLE_EXCEPT_ADVISED`](https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html#process-thp-controls)
for every worker before library loading. It prevents automatic, unadvised THP;
it does not change global sysfs policy. Unsupported kernels fail explicitly.
This provides a controlled comparison, not the incremental gain over an already
THP-enabled system. For BSS, global `always` or `madvise` must still allow
`MADV_HUGEPAGE`; under global `never`, BSS advice may have no effect. Always inspect
actual page counts. Use the same process policy for baseline comparisons.

`Loader::with_thp(policy)` also enables `MADV_HUGEPAGE` for anonymous BSS at the
same target size, including when the file policy is `Collapse`. BSS advice runs
before relocation and constructors, allowing allocation on first write without
synchronous collapse or eager page faults. Only complete huge pages inside
writable BSS of file-mapped images are eligible; file tail pages are excluded.
Overlapping LOADs receive advice on their final mappings. Sparse usage may increase
RSS. Hosts already using anonymous THP by default may see no additional benefit.

The `relink_thp` benchmark enables both; its page counts can therefore include BSS
huge pages. Regenerate baselines from versions where `with_thp` affected files only.

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
