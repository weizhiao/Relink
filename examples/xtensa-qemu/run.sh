#!/usr/bin/env bash
set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="xtensa-esp32-none-elf"
toolchain="${ESP_TOOLCHAIN:-esp}"
target_dir="${CARGO_TARGET_DIR:-$test_dir/target}"
if [[ "$target_dir" != /* ]]; then
    target_dir="$test_dir/$target_dir"
fi

die() {
    echo "error: $*" >&2
    exit 1
}

resolve_executable() {
    local executable="$1"
    if [[ -x "$executable" ]]; then
        printf '%s\n' "$executable"
    else
        command -v "$executable" 2>/dev/null
    fi
}

find_tool() {
    local name="$1"
    shift
    local root result
    for root in "$@"; do
        [[ -d "$root" ]] || continue
        result="$(find "$root" -type f -name "$name" -perm -111 -print -quit 2>/dev/null)"
        if [[ -n "$result" ]]; then
            printf '%s\n' "$result"
            return 0
        fi
    done
    return 1
}

if [[ -n "${ESP_EXPORT:-}" ]]; then
    [[ -f "$ESP_EXPORT" ]] || die "ESP_EXPORT does not exist: $ESP_EXPORT"
    source "$ESP_EXPORT"
elif ! command -v xtensa-esp32-elf-gcc >/dev/null 2>&1 &&
    [[ -f "$HOME/export-esp.sh" ]]; then
    source "$HOME/export-esp.sh"
fi

cargo_bin="$(resolve_executable "${CARGO:-cargo}" || true)"
espflash="$(resolve_executable "${ESPFLASH:-espflash}" || true)"
compiler="$(resolve_executable "${XTENSA_GCC:-xtensa-esp32-elf-gcc}" || true)"
qemu="$(resolve_executable "${QEMU_XTENSA:-qemu-system-xtensa}" || true)"

if [[ -z "$compiler" ]]; then
    compiler="$(find_tool xtensa-esp32-elf-gcc \
        "$HOME/.rustup/toolchains/$toolchain" \
        "$HOME/.espressif" || true)"
fi
if [[ -z "$qemu" ]]; then
    qemu="$(find_tool qemu-system-xtensa \
        "$HOME/.local/opt/qemu-xtensa" \
        "$HOME/.espressif" || true)"
fi

[[ -n "$cargo_bin" ]] || die "cargo was not found"
[[ -n "$espflash" ]] || die "espflash was not found; install it with 'cargo install espflash'"
[[ -n "$compiler" ]] || die "xtensa-esp32-elf-gcc was not found; run espup or set XTENSA_GCC"
[[ -n "$qemu" ]] || die "qemu-system-xtensa was not found; install Espressif QEMU or set QEMU_XTENSA"

mkdir -p "$target_dir"
log="$target_dir/qemu.log"
flash="$target_dir/xtensa-qemu.bin"
elf="$target_dir/$target/release/xtensa-qemu"

cd "$test_dir"
CARGO_TARGET_DIR="$target_dir" XTENSA_GCC="$compiler" \
    "$cargo_bin" "+$toolchain" build --release --target "$target"
"$espflash" save-image --chip esp32 --merge --ignore-app-descriptor "$elf" "$flash"

qemu_pid=
cleanup() {
    if [[ -n "$qemu_pid" ]]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
        qemu_pid=
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

"$qemu" \
    -nographic \
    -machine esp32 \
    -drive "file=$flash,if=mtd,format=raw" \
    -no-reboot >"$log" 2>&1 &
qemu_pid=$!

for _ in {1..200}; do
    if grep -q "fibonacci(10) = 55\\|load failed:" "$log"; then
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

cleanup
cat "$log"

if grep -q "Hello, World!" "$log" &&
    grep -q "fibonacci(10) = 55" "$log"; then
    exit 0
fi

echo "Xtensa QEMU example failed" >&2
exit 1
