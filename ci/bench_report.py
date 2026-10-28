"""Summarize this run's Criterion load, teardown, and symbol lookup measurements."""
import json
from pathlib import Path
import re
import sys

GROUP = 'load_teardown'
LOOKUP_GROUP = 'symbol_lookup'
IMPLEMENTATIONS = ('relink', 'libloading')
PHASES = ('load', 'teardown')
LOOKUP_CASES = ('hit', 'miss')


def benchmark_id(library, implementation, phase, group=GROUP):
    return f'{group}/{library}/{implementation}/{phase}'


def format_time(estimate, divisor=1000):
    interval = estimate['confidence_interval']
    return (f"{estimate['point_estimate'] / divisor:.2f} "
            f"[{interval['lower_bound'] / divisor:.2f}, {interval['upper_bound'] / divisor:.2f}]")


root = Path(sys.argv[1])
log = Path(sys.argv[2]).read_text()
libraries = sorted(set(re.findall(r'^workload\t([^\r\n]+)$', log, re.MULTILINE)))
if not libraries:
    raise SystemExit('no workloads found in run log')
required = {
    benchmark_id(library, implementation, phase)
    for library in libraries for implementation in IMPLEMENTATIONS
    for phase in PHASES
}
required.update(
    benchmark_id(library, implementation, case, LOOKUP_GROUP)
    for library in libraries for implementation in IMPLEMENTATIONS
    for case in LOOKUP_CASES
)
# Old result files alone must not count as measurements from this run.
analyzed = set(re.findall(r'Benchmarking ([^\r\n]+): Analyzing', log))
if missing := required - analyzed:
    raise SystemExit(f'incomplete measurements in this run: {sorted(missing)}')

estimates = {}
for path in root.glob('**/new/benchmark.json'):
    full_id = json.loads(path.read_text())['full_id']
    if full_id in required:
        if full_id in estimates:
            raise SystemExit(f'duplicate benchmark result: {full_id}')
        estimates[full_id] = json.loads(path.with_name('estimates.json').read_text())['mean']
if missing := required - estimates.keys():
    raise SystemExit(f'missing benchmark results: {sorted(missing)}')

print('# Library benchmarks\n')
print('## Load and teardown\n')
print('Warm page cache; fresh Relink context per iteration. Context creation/destruction and '
      'host imports are excluded; Relink teardown includes release and destruction '
      'of released modules. Native teardown is dlclose. '
      'Times: mean [95% CI] in µs. Ratio: Relink / libloading (lower is faster). '
      'Load and teardown are sampled independently.\n')
print('| Library | Phase | Relink (µs) | libloading (µs) | Ratio |')
print('|---|---|---:|---:|---:|')
for library in libraries:
    for phase in PHASES:
        relink = estimates[benchmark_id(library, 'relink', phase)]
        native = estimates[benchmark_id(library, 'libloading', phase)]
        ratio = relink['point_estimate'] / native['point_estimate']
        print(f'| {library} | {phase} | {format_time(relink)} | '
              f'{format_time(native)} | {ratio:.2f}× |')

print('\n## Symbol lookup\n')
print('Resident libraries; setup, loading and teardown excluded. Each iteration performs one '
      'get call, cycling through up to 32 prepared names. Hits are ordinary root exports; '
      'TLS and IFUNCs are excluded. Relink searches root exports, while libloading/dlsym '
      'can also search dependencies. Miss times include each API\'s error handling. '
      'Times: mean [95% CI] in ns per lookup. Ratio: Relink / libloading (lower is faster).\n')
print('| Library | Case | Relink (ns) | libloading (ns) | Ratio |')
print('|---|---|---:|---:|---:|')
for library in libraries:
    for case in LOOKUP_CASES:
        relink = estimates[benchmark_id(library, 'relink', case, LOOKUP_GROUP)]
        native = estimates[benchmark_id(library, 'libloading', case, LOOKUP_GROUP)]
        ratio = relink['point_estimate'] / native['point_estimate']
        print(f'| {library} | {case} | {format_time(relink, 1)} | '
              f'{format_time(native, 1)} | {ratio:.2f}× |')
