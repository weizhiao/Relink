# Test Layers

Relink's tests focus on the reusable ELF mechanisms exposed by this crate:

- `loader`: ELF classification, scanning, mapping, metadata reuse, and load-time errors.
- `relocator`: dynamic/object relocation and symbol resolution.
- `tls`: resolver integration, TLS relocations, and thread-local storage behavior.
- `lazy`: runtime binding, jump-slot updates, retained scopes, and failure modes.
- `linker`: dependency resolution, scan-first planning, context updates, and lifecycle staging.
- `observer`: loader, relocator, object, and linker event customization.

Component-flow tests use compiler-produced ELF files. Generated images are
reserved for malformed inputs, exact relocation layouts, and synthetic-module
behavior where byte-level control is part of the assertion.

Each component owns the fixtures that define its test scenarios. The generic
fixture compiler lives in `tests/fixture_build`. Tests do not reuse fixtures
from another component or from examples, so those scenarios can evolve
independently.

Architecture-specific end-to-end suites live under their component layer. For
example, `relocator::riscv64` cross-compiles real RISC-V objects and executes
the relocated code through cross's QEMU runner in CI.

End-to-end `dlopen`, `dlsym`, `RTLD_*`, process startup, and glibc compatibility
belong in the downstream `rust-dynlinker` test suite. Relink keeps only the
smoke coverage needed to verify that its components compose correctly.
