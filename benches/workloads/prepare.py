#!/usr/bin/env python3
"""Prepare pinned inputs for the Clang and NPB CG THP benchmarks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import urllib.request

DEST = Path(__file__).resolve().parents[2] / "target" / "thp-input"
SIMDJSON_VERSION = "3.12.3"
SIMDJSON_SOURCES = {
    "simdjson.cpp": "17a1e9b70a8cc0a5be3b3e95ddb26838bcebdc8bb6cb93980a9628b065cbaf72",
    "simdjson.h": "d930dbc24ecba8fb7fcba534e1932375964bb2fab82a396d3b810b42968c1863",
}
COMMIT = "5d565d916cad47bf09a2fa7432bf8e5fa95446ec"
CG_SOURCES = {
    "CG/cg.c": "9d31b513341ca602cc7d2e1b21bde1aa183be44400f919cdb632213c126543a2",
    "common/npb-C.h": "7c06f0cfecc4ef2ff8f89dc67a8aaa5752e56e4d05dd7da9dd94a0d3ea5a272c",
    "common/c_randdp.c": "0cb3e4d66bf4ed1e221c6d6f7c78f60a34a9684b8bad7fbc70de086b255d9938",
}


def fetch_sources(destination, base_url, sources):
    for name, expected in sources.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = path.read_bytes() if path.exists() else urllib.request.urlopen(
            f"{base_url}/{name}", timeout=60,
        ).read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"{name}: SHA-256 mismatch: {actual}")
        path.write_bytes(data)


def prepare_simdjson():
    compiler = shlex.split(os.environ.get("CLANGXX", "clang++"))
    subprocess.run([*compiler, "--version"], check=True)
    fetch_sources(DEST,
        f"https://raw.githubusercontent.com/simdjson/simdjson/v{SIMDJSON_VERSION}/singleheader",
        SIMDJSON_SOURCES)
    temporary = DEST / "simdjson.ii.tmp"
    try:
        subprocess.run([*compiler, "-std=c++17", "-E", "simdjson.cpp", "-o", temporary.name],
                       cwd=DEST, check=True)
        temporary.replace(DEST / "simdjson.ii")
    finally:
        temporary.unlink(missing_ok=True)
    output = DEST / "simdjson.ii"
    print(f"{hashlib.sha256(output.read_bytes()).hexdigest()}  {output}")


def prepare_cg(size):
    compiler = shlex.split(os.environ.get("CC", "cc"))
    subprocess.run([*compiler, "--version"], check=True)
    dest = DEST / "npb-cg"
    fetch_sources(dest,
        f"https://raw.githubusercontent.com/benchmark-subsetting/NPB3.0-omp-C/{COMMIT}",
        CG_SOURCES)
    build = dest / size
    build.mkdir(exist_ok=True)
    na, nonzer, iterations, shift = {
        "A": (14000, 11, 15, 20.0),
        "B": (75000, 13, 75, 60.0),
    }[size]
    defines = dict(NA=na, NONZER=nonzer, NITER=iterations, SHIFT=shift,
                   RCOND="1.0e-1", CONVERTDOUBLE="FALSE",
                   NPBVERSION='"3.0"', COMPILETIME='"pinned"')
    defines.update({f"CS{i}": '"see manifest.json"' for i in range(1, 8)})
    (build / "npbparams.h").write_text("".join(
        f"#define {key} {value}\n" for key, value in defines.items()))

    # Preserve the algorithm and original verification; export its final zeta.
    source = (dest / "CG/cg.c").read_text()
    marker = '    c_print_results("CG",'
    assert source.count(marker) == 1
    source = ("extern double relink_cg_zeta;\n"
              "extern int relink_cg_quiet_printf(const char *, ...);\n") + source.replace(
        marker, '    relink_cg_zeta = zeta;\n' + marker)
    source = re.sub(r"\bprintf\s*\(", "relink_cg_quiet_printf(", source)
    (build / "cg.c").write_text(source)
    output = dest / f"libnpb-cg-{size}.so"
    temporary = output.with_suffix(".so.tmp")
    adapter = Path(__file__).with_name("cg_adapter.c")
    command = [*compiler, "-O3", "-std=gnu99", "-fPIC", "-shared",
               "-Wl,-z,max-page-size=2097152,-Bsymbolic", "-Dmain=npb_main",
               f"-I{build}", f"-I{dest / 'common'}",
               str(build / "cg.c"), str(dest / "common/c_randdp.c"), str(adapter),
               "-lm", "-o", str(temporary)]
    try:
        subprocess.run(command, check=True)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    (build / "manifest.json").write_text(json.dumps({
        "commit": COMMIT, "sources": CG_SOURCES, "class": size, "command": command,
        "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        "library_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }, indent=2) + "\n")
    print(f"NPB_CG_LIBRARY={output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="workload", required=True)
    commands.add_parser("simdjson", help="preprocess simdjson.cpp with CLANGXX")
    cg = commands.add_parser("cg", help="build the serial NPB CG library with CC")
    cg.add_argument("--class", choices=["A", "B"], default="B", dest="size")
    args = parser.parse_args()
    if args.workload == "simdjson":
        prepare_simdjson()
    else:
        prepare_cg(args.size)


if __name__ == "__main__":
    main()
