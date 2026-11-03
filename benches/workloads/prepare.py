#!/usr/bin/env python3
"""Prepare pinned inputs for the Clang and LLVM THP benchmarks."""
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import urllib.request

DEST = Path(__file__).resolve().parents[2] / "target" / "thp-input"
SIMDJSON_VERSION = "3.12.3"
SIMDJSON_SOURCES = {
    "simdjson.cpp": "17a1e9b70a8cc0a5be3b3e95ddb26838bcebdc8bb6cb93980a9628b065cbaf72",
    "simdjson.h": "d930dbc24ecba8fb7fcba534e1932375964bb2fab82a396d3b810b42968c1863",
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


def prepare_llvm():
    prepare_simdjson()
    compiler = shlex.split(os.environ.get("CLANGXX", "clang++"))
    temporary = DEST / "simdjson.bc.tmp"
    try:
        # Generate real frontend IR without pre-running the optimization pipeline.
        # -O1 avoids optnone; the benchmark itself runs default<O3>.
        subprocess.run([*compiler, "-std=c++17", "-O1", "-Xclang", "-disable-llvm-passes",
                        "-emit-llvm", "-c", "simdjson.ii", "-o", temporary.name],
                       cwd=DEST, check=True)
        temporary.replace(DEST / "simdjson.bc")
    finally:
        temporary.unlink(missing_ok=True)
    output = DEST / "simdjson.bc"
    print(f"{hashlib.sha256(output.read_bytes()).hexdigest()}  {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="workload", required=True)
    commands.add_parser("simdjson", help="preprocess simdjson.cpp with CLANGXX")
    commands.add_parser("llvm", help="prepare unoptimized simdjson bitcode with CLANGXX")
    args = parser.parse_args()
    if args.workload == "llvm":
        prepare_llvm()
    else:
        prepare_simdjson()


if __name__ == "__main__":
    main()
