#!/usr/bin/env sh

set -ex

: "${TARGET?The TARGET environment variable must be set.}"

export CARGO_NET_RETRY=5
export CARGO_NET_TIMEOUT=30
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
export CARGO_HTTP_MULTIPLEXING=false

install_cross() {
	attempt=1
	while [ "${attempt}" -le 3 ]; do
		if cargo install --locked cross --git https://github.com/cross-rs/cross; then
			return 0
		fi

		attempt=$((attempt + 1))
		if [ "${attempt}" -le 3 ]; then
			sleep 5
		fi
	done

	return 1
}

# Use cargo for x86_64 if it's not a bare-metal (none) target, as those require specialized sysroots or build-std.
if echo "${TARGET}" | grep -q "x86_64"; then
	CARGO=cargo
	rustup target add "${TARGET}" || true
else
	if ! command -v cross >/dev/null 2>&1; then
		install_cross
	fi
	CARGO=cross
fi

cargo clean

if [ "${MINI_LOADER}" = "1" ]; then
	cargo run --example build_fixtures -- exec-a
	"${CARGO}" build --target="${TARGET}"
	"${CARGO}" ${OP} --target="${TARGET}" ${ARGS}
else
	"${CARGO}" ${OP} --target="${TARGET}" --no-default-features --features "${FEATURES}"
fi
