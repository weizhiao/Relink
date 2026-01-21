#!/usr/bin/env sh

set -ex

: "${TARGET?The TARGET environment variable must be set.}"

export CARGO_NET_RETRY=5
export CARGO_NET_TIMEOUT=10

# Use cargo for x86_64 if it's not a bare-metal (none) target, as those require specialized sysroots or build-std.
if echo "${TARGET}" | grep -q "x86_64"; then
	CARGO=cargo
	rustup target add "${TARGET}" || true
else
	cargo install --locked cross --git https://github.com/cross-rs/cross
	CARGO=cross
fi

cargo clean

if [ "${MINI_LOADER}" = "1" ]; then
	"${CARGO}" build --target="${TARGET}"
	"${CARGO}" ${OP} --target="${TARGET}" ${ARGS}
else
	"${CARGO}" -vv ${OP} --target="${TARGET}" --no-default-features --features "${FEATURES}"
fi
