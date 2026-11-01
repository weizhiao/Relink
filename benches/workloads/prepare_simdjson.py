#!/usr/bin/env python3
"""Download pinned simdjson sources and preprocess the THP benchmark input."""
import hashlib
import os
from pathlib import Path
import subprocess
import urllib.request

DEST = Path(__file__).resolve().parents[2] / "target" / "thp-input"
VERSION = "3.12.3"
SOURCES = {
    "simdjson.cpp": "17a1e9b70a8cc0a5be3b3e95ddb26838bcebdc8bb6cb93980a9628b065cbaf72",
    "simdjson.h": "d930dbc24ecba8fb7fcba534e1932375964bb2fab82a396d3b810b42968c1863",
}


def main():
    compiler = os.environ.get("CLANGXX", "clang++-18")
    subprocess.run([compiler, "--version"], check=True)
    DEST.mkdir(parents=True, exist_ok=True)
    for name, expected in SOURCES.items():
        path = DEST / name
        data = path.read_bytes() if path.exists() else urllib.request.urlopen(
            f"https://raw.githubusercontent.com/simdjson/simdjson/v{VERSION}/singleheader/{name}",
            timeout=60,
        ).read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"{name}: SHA-256 mismatch: {actual}")
        path.write_bytes(data)
    # Publish the input only when preprocessing succeeds. Relative source names
    # keep the project checkout path out of line markers.
    temporary = DEST / "simdjson.ii.tmp"
    try:
        subprocess.run([
            compiler, "-std=c++17", "-E", "simdjson.cpp", "-o", temporary.name,
        ], cwd=DEST, check=True)
        temporary.replace(DEST / "simdjson.ii")
    finally:
        temporary.unlink(missing_ok=True)
    output = DEST / "simdjson.ii"
    print(f"{hashlib.sha256(output.read_bytes()).hexdigest()}  {output}")


if __name__ == "__main__":
    main()
