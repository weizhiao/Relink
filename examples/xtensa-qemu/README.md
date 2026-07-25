# Xtensa QEMU Example

This example runs Relink on an ESP32 emulated by QEMU. The firmware:

- loads an Xtensa shared library into RTC Fast Memory;
- provides the shared library with a host `print` symbol;
- calls its exported `hello()` and `fibonacci()` functions.

## Setup

Install the Xtensa Rust toolchain and `espflash`:

```sh
cargo install espup --locked
espup install
cargo install espflash --locked
```

Install Espressif QEMU with ESP32 support. If
[ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html)
is already installed:

```sh
python "$IDF_PATH/tools/idf_tools.py" install qemu-xtensa
```

See the official [Rust toolchain setup](https://docs.espressif.com/projects/rust/book/getting-started/toolchain.html)
and [QEMU guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/tools/qemu.html)
for platform-specific dependencies.

## Run

Run the example from the repository root:

```sh
./examples/xtensa-qemu/run.sh
```

The relevant runtime output is:

```text
Hello, World!
fibonacci(10) = 55
```

The script builds the shared library and firmware, creates the ESP32 flash
image, runs QEMU, and verifies this output automatically.

Tools are discovered from `PATH`, a standard `espup` installation, and common
Espressif QEMU locations. For non-standard installations, set `ESP_EXPORT`,
`ESP_TOOLCHAIN`, `XTENSA_GCC`, `QEMU_XTENSA`, `ESPFLASH`, or
`CARGO_TARGET_DIR`.
