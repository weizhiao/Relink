#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CARGO_OUTPUT_DIR=${CARGO_TARGET_DIR:-"$ROOT_DIR/target"}
TEST_ROOT=${ELF_TEST_DIR:-"$ROOT_DIR"}
OUT_DIR="$TEST_ROOT/target/riscv64-test"
SYSROOT=${RISCV64_SYSROOT:-/usr/riscv64-linux-gnu}
LINKER=${RISCV64_LINKER:-riscv64-linux-gnu-gcc}
AR=${RISCV64_AR:-riscv64-linux-gnu-ar}
CARGO=${CARGO:-cargo}
RUSTFLAGS=${RISCV64_RUSTFLAGS:-"-C target-cpu=generic-rv64 -C target-feature=+m,+a,+f,+d,+c,+crt-static"}
CFLAGS=${RISCV64_CFLAGS:-"-march=rv64gc -mabi=lp64d"}
BUILD_STD_ARGS=${RISCV64_BUILD_STD_ARGS:-"-Z build-std=std,panic_unwind"}
CLANG=${RISCV64_CLANG:-clang}
LLD=${RISCV64_LLD:-ld.lld}
USE_LLD=${RISCV64_USE_LLD:-1}
IS_CROSS=0

case "$CARGO" in
  cross|*/cross)
    IS_CROSS=1
    ;;
esac

if [ "$IS_CROSS" = "0" ] && [ "$USE_LLD" = "1" ] && command -v "$CLANG" >/dev/null 2>&1 && command -v "$LLD" >/dev/null 2>&1; then
  LINKER="$CLANG"
  GCC_LIB_PATH="/usr/lib/gcc-cross/riscv64-linux-gnu/14"
  CFLAGS="$CFLAGS --target=riscv64-linux-gnu --sysroot=$SYSROOT -fuse-ld=lld -L$GCC_LIB_PATH"
  RUSTFLAGS="$RUSTFLAGS -C link-arg=--target=riscv64-linux-gnu -C link-arg=--sysroot=$SYSROOT -C link-arg=-fuse-ld=lld -C link-arg=-L$GCC_LIB_PATH -C link-arg=-B$GCC_LIB_PATH"
fi

if ! command -v "$LINKER" >/dev/null 2>&1; then
  echo "Missing linker ($LINKER). Install it or run via Docker." >&2
  exit 1
fi

if ! command -v qemu-riscv64 >/dev/null 2>&1; then
  echo "Missing qemu-riscv64. Install qemu-user or run via Docker." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "Compiling comprehensive RISC-V relocation tests..."

"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/a.c" -o "$OUT_DIR/a.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/b.c" -o "$OUT_DIR/b.o"

# 编译所有测试模块
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_call.c" -o "$OUT_DIR/test_call.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_globals.c" -o "$OUT_DIR/test_globals.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_branches.c" -o "$OUT_DIR/test_branches.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_hi_lo.c" -o "$OUT_DIR/test_hi_lo.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_pointers.c" -o "$OUT_DIR/test_pointers.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_32bit.c" -o "$OUT_DIR/test_32bit.o"
"$LINKER" $CFLAGS -fPIC -c "$ROOT_DIR/tests/fixtures/riscv64/test_main.c" -o "$OUT_DIR/test_main.o"

echo "Compiled all test modules successfully!"
echo ""
echo "Analyzing relocations in test modules:"
echo "========================================"

# 显示每个模块的重定位类型统计
for obj in test_call test_globals test_branches test_hi_lo test_pointers test_32bit test_main; do
  echo ""
  echo "Module: $obj.o"
  echo "----------------------------------------"
  if command -v riscv64-linux-gnu-readelf >/dev/null 2>&1; then
    riscv64-linux-gnu-readelf -r "$OUT_DIR/$obj.o" 2>/dev/null | grep -E "R_RISCV_" | awk '{print $3}' | sort | uniq -c || true
  fi
done

echo ""
echo "========================================"
echo ""

cd "$ROOT_DIR"
resolve_test_exe() {
  exe="$1"
  case "$exe" in
    /target/*)
      printf '%s\n' "$CARGO_OUTPUT_DIR${exe#/target}"
      ;;
    *)
      printf '%s\n' "$exe"
      ;;
  esac
}

build_test_exe() {
  name="$1"
  exe=$(RUSTFLAGS="$RUSTFLAGS" \
    CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUSTFLAGS="$RUSTFLAGS" \
    CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="$LINKER" \
    CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_AR="$AR" \
    "$CARGO" test --features object,log,riscv64-tests $BUILD_STD_ARGS --test "$name" \
      --target riscv64gc-unknown-linux-gnu --no-run --message-format=json | \
    awk -v name="$name" 'index($0, "\"name\":\"" name "\"") && index($0, "\"executable\"") { match($0, /"executable":"([^"]+)"/, m); if (m[1] != "") { print m[1]; } }' | \
    tail -n 1)

  if [ -z "$exe" ]; then
    echo "Failed to locate test executable for $name" >&2
    exit 1
  fi

  resolve_test_exe "$exe"
}

echo "Building Rust test binaries..."
OBJECT_LINK_EXE=$(build_test_exe riscv64_object_link)
RELOC_TEST_EXE=$(build_test_exe riscv64_reloc_test)

echo ""
echo "Running object-link example..."
echo "========================================"
cd "$ROOT_DIR"
qemu-riscv64 -L "$SYSROOT" \
  -E ELF_TEST_DIR="$TEST_ROOT" \
  "$OBJECT_LINK_EXE"

echo ""
echo "Running comprehensive relocation tests..."
echo "========================================"
cd "$ROOT_DIR"
qemu-riscv64 -L "$SYSROOT" \
  -E ELF_TEST_DIR="$TEST_ROOT" \
  "$RELOC_TEST_EXE"

echo ""
echo "========================================"
echo "All tests completed successfully!"
