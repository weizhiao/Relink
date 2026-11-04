# Performance benchmarks

Requires Linux/glibc. Use a fixed CPU affinity on an idle machine and regenerate
baselines after harness changes.

## TLS access

On Linux/glibc x86_64, compare Relink's default TLS resolver with glibc using
the same small shared library. Requires a GCC-compatible C compiler (`CC`,
default `cc`) supporting `-mtls-dialect=gnu`.

```sh
# Replace 2 with an available CPU; child processes and threads inherit affinity.
taskset -c 2 cargo bench --bench tls --features std,version
cargo bench --bench tls --features std,version -- --test
# Criterion options and filters are forwarded to both loader workers.
taskset -c 2 cargo bench --bench tls --features std,version -- first_access
```

The fixture is compiled once per invocation, outside measurement, and copied into
10 separately loaded modules, each with its own 8-byte initialized TLS counter.
Both loaders use the identical general-dynamic TLS access sequence and eager
symbol binding, in separate processes. The shared libraries remain under
`target/tls-bench/<pid>/`.

| Case | Measured work |
| --- | --- |
| `hot_10_modules` | Round-robin calls to all 10 modules after initialization: function calls, TLS address resolution, reads and increments. |
| `first_access_10_modules` | One increment per module in each fresh thread: first TLS address resolution and block initialization for all 10 modules, including per-thread resolver bookkeeping. |

For `first_access_10_modules`, timestamps are taken inside the new thread. Thread creation,
join, TLS destruction and correctness checks are excluded; the clock is warmed
before timing. Timer overhead remains included and is not subtracted. This is
first access to each module in a thread, not a cold instruction/data-cache test.
Each thread must observe every module's initial value and its own incremented value, and
preflight checks verify that a child cannot modify its parent's TLS counter.
No TLS lookup prewarms the measured thread's fixture modules before the first access.

Both cases use 10 modules with independent initial state. Reported latency covers
10 calls, while Criterion's element throughput counts individual accesses.

Criterion defaults are 1 s warmup, 2 s requested measurement and 30 samples.
Results go to `target/criterion/tls_access/`. These cases do not measure module
load/unload, static TLS, TLSDESC, or concurrent-thread scalability.

## THP execution

Choose `THP_WORKLOAD=clang` (default) or `THP_WORKLOAD=llvm`. Both compare
Relink, Relink with THP, and glibc in separate processes.

Both workloads use Criterion sampling, with correctness checks and before/after
page counts. Use `-- --test` for a functional check without statistical sampling.

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

LLVM optimizes simdjson bitcode with `default<O3>` and emits a native object,
exercising the large code mapping in libLLVM. It requires matching Clang/libLLVM
versions (21.1.8 was tested); this workload initializes x86_64 or AArch64 targets:

```sh
python3 benches/workloads/prepare.py llvm
THP_WORKLOAD=llvm taskset -c 0 cargo bench --bench thp --features std,version
THP_WORKLOAD=llvm cargo bench --bench thp --features std,version -- --test
```

`LLVM_LIBRARY` overrides `llvm-config --link-shared --libfiles`; `LLVM_INPUT`
overrides `target/thp-input/simdjson.bc`. Only optimization and object emission
are timed; IR setup, verification, output hashing and teardown are excluded.
Outputs are checked before and after sampling. Object lengths and hashes must match across loaders. See the
[input and validation details](workloads/README.md#llvm-optimization-and-code-generation).

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

Defaults: 1 s warmup, 5 s requested measurement, and 30 Clang or 10 LLVM
samples. Actual measurement time can exceed 5 s to meet the sample count.
Criterion command-line options are forwarded, with results under
`target/criterion/thp_clang/` or `target/criterion/thp_llvm/`. Output groups timings
and before/after huge-page counts by case, then checks that all
AST node counts and cursor-kind hashes match for Clang. Error diagnostics fail validation.
These are structural sanity checks, not semantic-equivalence proofs. Compare
runs using the same libclang and input.

The mapping table reports MiB from `/proc/self/smaps`: `FilePmdMapped`,
`AnonHugePages`, `ShmemPmdMapped`, and RSS. `Partial VMAs` overlap the image boundary
and are excluded from counts. Zero counts with no partial VMAs mean no PMD huge
pages were observed at those snapshots. Counts cover the selected root library,
including its BSS; dependencies and heap allocations are excluded. Both snapshots
follow the initial validation run.

Collapse failures do not abort loading. Check actual page counts: default loaders
may also use THP. THP policies choose an ELF-compatible load bias that maximizes
executable coverage, then total non-writable coverage; they can change alignment as
well as page backing. Separate processes still share the file cache, so timings
alone do not isolate THP gains.

`Loader::with_thp(ThpPolicy::Advise)` or `ThpPolicy::Collapse` selects the policy;
the mapping backend supplies the size through `Mmap::thp_page_size()`. The default
Linux backend reads and caches `/sys/kernel/mm/transparent_hugepage/hpage_pmd_size`.
Missing or invalid sizes disable THP optimization without failing the load.
Custom backends can provide their own size; the trait default is `None`.

Both policies also enable `MADV_HUGEPAGE` for anonymous BSS at the same target
size, including when the file policy is `Collapse`. BSS advice runs
before relocation and constructors, allowing allocation on first write without
synchronous collapse or eager page faults. Only complete huge pages inside
writable BSS of file-mapped images are eligible; file tail pages are excluded.
Overlapping LOADs receive advice on their final mappings. Sparse usage may increase
RSS. Hosts already using anonymous THP by default may see no additional benefit.

The same API supports inputs copied into anonymous memory, such as `ElfBinary`.
All LOADs, including writable data and BSS, receive `MADV_HUGEPAGE` before copying.
`Collapse` also attempts to merge complete huge pages of initialized contents
after copying and before final segment protections. BSS is not synchronously
collapsed. File-offset alignment is irrelevant to copied inputs; only destination
addresses must align. Section arenas and borrowed mappings remain excluded.

The `relink_thp` benchmark enables both; its page counts can therefore include BSS
huge pages. Regenerate baselines from versions where `with_thp` affected files only.

### THP figure

The README figure uses measurements from commit `a451175`,
collected on 2026-11-03: Ryzen 9 7945HX, Linux 7.0.11, glibc 2.43, Rust 1.96.0,
CPU 2, system THP `always`, defrag `madvise`. The CPU governor remained `powersave`
with `balance_performance`; no system settings or caches were reset.
Libclang/libLLVM 21.1.8 process simdjson 3.12.3. Each backend/workload received
one functional warmup before measurement, sharing a warm file cache.

Execution uses the current Criterion harness: 1 s warmup, 5 s requested
measurement, 30 Clang or 10 LLVM samples, one process per backend/workload.
Actual measurement time exceeds 5 s when needed to collect the samples.
The figure shows mean time and Criterion's 95% confidence interval; loading,
collapse, setup, correctness checks and teardown are excluded. Both axes start
at zero. The figure compares default Relink with `ThpPolicy::Collapse`.

Instruction TLB counts come from separate `perf stat` runs with `--test`.
Criterion 0.8.2 executes one test iteration; together with validation before and
after, each worker performs exactly **three parses or compilations**. Two fresh
processes per backend/workload run in forward then reverse loader order on CPU 2.
All counters ran for 100% of the interval. Counts include the entire user-mode
worker: loading, setup, validation and teardown. Their means have no confidence
intervals. These are instruction TLB misses, not all TLB misses.
THP changes mapping alignment as well as page backing,
so the comparison does not isolate those effects.

To collect counters after preparing the inputs and building the benchmark,
use the executable printed by `cargo bench --bench thp --features std,version --no-run`:

```sh
# Repeat for clang / llvm and relink / relink_thp / glibc.
# Set library to the matching libclang or libLLVM shared object.
THP_WORKLOAD=clang _RELINK_THP_BACKEND=relink _RELINK_THP_LIBRARY=/path/to/library.so \
  perf stat -e cycles:u,instructions:u,iTLB-load-misses:u,dTLB-load-misses:u -- \
  taskset -c 2 /path/to/thp-executable --bench --test --noplot
```

Root-library file PMD coverage rose from 0 to 18 MiB for Clang and
0 to 60 MiB for LLVM. In the timing runs, root-library RSS increased from
21.0 to 26.8 MiB and from 62.6 to 80.9 MiB, respectively; dependencies and heap
memory are excluded from those page counts.

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
