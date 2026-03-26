#![allow(dead_code)]

use gen_elf::Arch;
use std::path::{Path, PathBuf};

pub(crate) fn return_42_stub(arch: Arch) -> Vec<u8> {
    match arch {
        Arch::X86_64 | Arch::X86 => vec![0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3],
        Arch::Aarch64 => vec![0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
        Arch::Riscv64 | Arch::Riscv32 => vec![0x13, 0x05, 0xa0, 0x02, 0x67, 0x80, 0x00, 0x00],
        Arch::Arm => vec![0x2a, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1],
        Arch::Loongarch64 => vec![0x04, 0xa8, 0x80, 0x02, 0x20, 0x00, 0x00, 0x4c],
    }
}

pub(crate) fn generated_dylib_path(test_name: &str, arch: Arch) -> PathBuf {
    PathBuf::from("/tmp").join(format!("{test_name}_{arch:?}.so"))
}

#[cfg(unix)]
pub(crate) unsafe fn load_unix_library(path: &Path) -> libloading::Library {
    let path = path
        .to_str()
        .expect("failed to convert generated library path to string");
    let library = unsafe {
        libloading::os::unix::Library::open(Some(path), libloading::os::unix::RTLD_LAZY)
            .expect("failed to load library with libloading")
    };
    libloading::Library::from(library)
}
