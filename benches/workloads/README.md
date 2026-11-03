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

## LLVM optimization and code generation

```sh
python3 benches/workloads/prepare.py llvm
THP_WORKLOAD=llvm cargo bench --bench thp --features std,version
```

This reuses the same pinned simdjson sources and first prepares `simdjson.ii`.
It then invokes the matching `CLANGXX` compiler (default `clang++`):

```sh
clang++ -std=c++17 -O1 -Xclang -disable-llvm-passes -emit-llvm -c simdjson.ii -o simdjson.bc
```

`-O1` avoids `optnone` attributes; `-disable-llvm-passes` leaves optimization to
the benchmark. The complete frontend-generated module is used without synthetic
code expansion. Both generated inputs stay under `target/thp-input/`; the script
prints their SHA-256 hashes. Use a compiler matching the measured libLLVM version.
`LLVM_INPUT` selects a frozen bitcode file; `LLVM_LIBRARY` selects its monolithic
shared libLLVM. Otherwise the library comes from `llvm-config --link-shared --libfiles`.

Each repetition clones the original module, runs LLVM's
[`default<O3>` pipeline](https://llvm.org/doxygen/group__LLVMCCoreNewPM.html),
and emits a PIC native ELF object in memory. The input fixes the target triple
and function attributes; the target machine uses the generic CPU and aggressive
code generation. Only optimization and object emission are timed. Bitcode reads,
parsing, module cloning, IR verification, output hashing and teardown are excluded.

LLVM verifies the input and compiled modules. Object length and an FNV-1a hash
must match across repetitions and loaders. This checks reproducibility of emitted
bytes; it does not run the object or prove semantic equivalence.

The workload exercises the optimizer and backend code in the mapped libLLVM,
where file-backed code pages can benefit from THP even when anonymous heap THP
is already automatic. Whether this helps a particular machine must be established
from both timings and actual page coverage. It measures compilation, not execution
of generated simdjson code.
