"""Real CPython work on installed standard-library sources, prepared before timing."""
import gc
import json
import os

STDLIB = os.path.dirname(os.__file__)
MODULES = (
    "argparse.py",
    "ast.py",
    "dataclasses.py",
    "difflib.py",
    "inspect.py",
    "pydoc.py",
    "typing.py",
    "asyncio/base_events.py",
    "unittest/mock.py",
)

sources = []
for name in MODULES:
    with open(os.path.join(STDLIB, name), encoding="utf-8") as source:
        sources.append((name, source.read()))

# A source-index export: JSON escaping, UTF-8 text, nested metadata, and lists.
records = [
    {"path": name, "source": text, "metadata": {"lines": text.count("\n"), "bytes": len(text.encode())}}
    for name, text in sources
]
document = json.dumps(records, ensure_ascii=False, sort_keys=True)
expected_json_size = len(document)
print("python_input\tfiles=%d\tsource_bytes=%d\tjson_chars=%d" % (
    len(sources), sum(len(text.encode()) for _, text in sources), expected_json_size
), flush=True)
print("python_json\tdecoder=%s\tC_encoder=%s" % (
    json.decoder.scanstring.__module__, json.encoder.c_make_encoder is not None
), flush=True)


def stdlib_compile():
    """Parse and compile real modules to bytecode without executing or writing them."""
    return sum(len(compile(text, name, "exec", dont_inherit=True).co_code)
               for name, text in sources)


def json_roundtrip():
    """Decode and re-encode the source-index document using CPython's JSON stack."""
    decoded = json.loads(document)
    encoded = json.dumps(decoded, ensure_ascii=False, sort_keys=True)
    assert len(encoded) == expected_json_size
    return len(encoded)


# Check the complete output once, outside timing, then stabilize the heap.
assert json.loads(document) == records
assert stdlib_compile() > 0
assert json_roundtrip() == expected_json_size
gc.collect()
