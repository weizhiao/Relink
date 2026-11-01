# THP workload inputs

## simdjson frontend input

The THP benchmark parses and type-checks the complete C++17 translation unit
[`singleheader/simdjson.cpp` from simdjson 3.12.3](https://github.com/simdjson/simdjson/tree/v3.12.3/singleheader)
using libclang. It includes function bodies; it does not generate code or run
simdjson's JSON parser.

Prepare the input once, from the repository root:

```sh
python3 benches/workloads/prepare.py simdjson
```

The script downloads `simdjson.cpp` and `simdjson.h` from the pinned release,
verifies their SHA-256 hashes, and runs:

```sh
cd target/thp-input
clang++ -std=c++17 -E simdjson.cpp -o simdjson.ii
```

The system `clang++` is used by default; set `CLANGXX` to override it.

Sources and generated input stay under `target/thp-input/`; they are not bundled
in the repository. The upstream sources carry their Apache-2.0/MIT license
notices. Preprocessing also incorporates local C++ and system headers.
Use a Clang compiler compatible with the libclang being measured; Clang 18 and
libclang 18.1.1 were used for the workload-selection experiment. Changing system
headers or the compiler can change the input and AST. Retain the same `.ii` file
and library for comparisons; the script prints the generated input's SHA-256.
To reuse a frozen input on another machine, set `SIMDJSON_INPUT=/path/simdjson.ii`.
The benchmark does not download or preprocess anything during a run.

| Source | SHA-256 |
|---|---|
| `simdjson.cpp` | `17a1e9b70a8cc0a5be3b3e95ddb26838bcebdc8bb6cb93980a9628b065cbaf72` |
| `simdjson.h` | `d930dbc24ecba8fb7fcba534e1932375964bb2fab82a396d3b810b42968c1863` |

The earlier selection experiment used a frozen `.ii` with SHA-256
`3206cf6d3eeefad2c6cf4776364f485ffea3a23314db4539d8bef80ec8db8a64`.
That hash identifies the measured artifact; it is not a portable expected hash
for regeneration against different system headers.

## NPB CG BSS workload

The [unofficial NPB 3.0 OpenMP C port](https://github.com/benchmark-subsetting/NPB3.0-omp-C)
is built serially, without OpenMP, from commit
`5d565d916cad47bf09a2fa7432bf8e5fa95446ec`:

```sh
python3 benches/workloads/prepare.py cg            # Class B
python3 benches/workloads/prepare.py cg --class A  # smaller, faster validation
```

| Class | Matrix dimension | Nonzeros parameter | Iterations | Shift | Approximate BSS |
|---|---:|---:|---:|---:|---:|
| A | 14,000 | 11 | 15 | 20 | 59.5 MiB |
| B | 75,000 | 13 | 75 | 60 | 427 MiB |

The script verifies pinned source hashes, retains upstream permission notices,
and writes sources, generated files and shared libraries under
`target/thp-input/npb-cg/`. `CC` selects the compiler. Each class's `manifest.json`
records the compile command, source hashes, adapter hash and resulting library
hash. All loader cases use the same resulting binary. The 2 MiB ELF alignment is
identical in all cases; no arrays or numerical loops are rearranged.

The adapter in `cg_adapter.c` exports a callable entry point, captures the original
NPB verification result and final eigenvalue, suppresses progress printing, and
uses a monotonic clock at the original timer boundaries. The algorithm and its
reference eigenvalue/tolerance are unchanged. Compilation uses `-O3 -fPIC -shared`
and `-Wl,-z,max-page-size=2097152,-Bsymbolic`; it does not enable fast math.
Class B's verification reference is `22.712745482631`, with tolerance `1e-10`.

| Source | SHA-256 |
|---|---|
| `CG/cg.c` | `9d31b513341ca602cc7d2e1b21bde1aa183be44400f919cdb632213c126543a2` |
| `common/npb-C.h` | `7c06f0cfecc4ef2ff8f89dc67a8aaa5752e56e4d05dd7da9dd94a0d3ea5a272c` |
| `common/c_randdp.c` | `0cb3e4d66bf4ed1e221c6d6f7c78f60a34a9684b8bad7fbc70de086b255d9938` |
