#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
use elf_loader::{Error, error::ParseEhdrError};
use elf_loader::{
    Loader,
    elf::{ElfFileType, ElfProgramType},
    image::ScannedElf,
    input::ElfBinary,
};
use std::sync::OnceLock;

const LOADER: Loader = Loader::new();
const E_TYPE_OFFSET: usize = 0x10;
#[cfg(target_pointer_width = "64")]
const E_PHOFF_OFFSET: usize = 0x20;
#[cfg(not(target_pointer_width = "64"))]
const E_PHOFF_OFFSET: usize = 0x1c;
#[cfg(target_pointer_width = "64")]
const E_PHENTSIZE_OFFSET: usize = 0x36;
#[cfg(not(target_pointer_width = "64"))]
const E_PHENTSIZE_OFFSET: usize = 0x2a;
#[cfg(target_pointer_width = "64")]
const E_PHNUM_OFFSET: usize = 0x38;
#[cfg(not(target_pointer_width = "64"))]
const E_PHNUM_OFFSET: usize = 0x2c;

fn mark_as_static_exec(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[E_TYPE_OFFSET..E_TYPE_OFFSET + 2].copy_from_slice(&ElfFileType::EXEC.raw().to_le_bytes());
    #[cfg(target_pointer_width = "64")]
    let phoff = u64::from_le_bytes(
        bytes[E_PHOFF_OFFSET..E_PHOFF_OFFSET + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    #[cfg(not(target_pointer_width = "64"))]
    let phoff = u32::from_le_bytes(
        bytes[E_PHOFF_OFFSET..E_PHOFF_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let phentsize = u16::from_le_bytes(
        bytes[E_PHENTSIZE_OFFSET..E_PHENTSIZE_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let phnum = u16::from_le_bytes(
        bytes[E_PHNUM_OFFSET..E_PHNUM_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;

    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let p_type = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        if p_type == ElfProgramType::DYNAMIC.raw() {
            bytes[offset..offset + 4].copy_from_slice(&ElfProgramType::NULL.raw().to_le_bytes());
            return bytes;
        }
    }

    panic!("compiled test image should contain PT_DYNAMIC");
}

fn static_exec() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| mark_as_static_exec(crate::fixture::fixtures().exec.clone()))
}

#[test]
fn loads_dylib() {
    let loaded = LOADER
        .load_dylib(ElfBinary::new(
            "provider.so",
            &crate::fixture::fixtures().dylib,
        ))
        .expect("load_dylib should accept ET_DYN");

    assert_eq!(loaded.path().as_str(), "provider.so");
    assert!(
        loaded
            .phdrs()
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
    );
}

#[test]
#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
fn loads_exec() {
    let bytes = crate::fixture::fixtures().exec.as_slice();

    let error = LOADER
        .load_dylib(ElfBinary::new("dynamic_exec", bytes))
        .expect_err("load_dylib should reject ET_EXEC");
    assert!(matches!(
        error,
        Error::ParseEhdr(ParseEhdrError::ExpectedDylib { found })
            if found == ElfFileType::EXEC
    ));

    let loaded = LOADER
        .load_dynamic(ElfBinary::new("dynamic_exec", bytes))
        .expect("load_dynamic should accept dynamic ET_EXEC");
    assert!(
        loaded
            .phdrs()
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
    );
}

#[test]
#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
fn loads_scanned_exec() {
    let ScannedElf::Dynamic(scanned) = LOADER
        .scan(ElfBinary::new(
            "scanned_dynamic_exec",
            &crate::fixture::fixtures().exec,
        ))
        .expect("scan should accept dynamic ET_EXEC")
    else {
        panic!("dynamic ET_EXEC should scan as dynamic");
    };
    assert_eq!(scanned.ehdr().file_type(), ElfFileType::EXEC);
    let phdr_count = scanned.phdrs().len();

    let loaded = LOADER
        .load_scanned_dynamic(scanned)
        .expect("load_scanned_dynamic should accept dynamic ET_EXEC");
    assert_eq!(loaded.phdrs().len(), phdr_count);
    assert!(
        loaded
            .phdrs()
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
    );
}

#[test]
fn classifies_images() {
    let ScannedElf::Dynamic(dynamic) = LOADER
        .scan(ElfBinary::new(
            "scanned.so",
            &crate::fixture::fixtures().dylib,
        ))
        .expect("scan should accept dynamic image")
    else {
        panic!("PT_DYNAMIC image should scan as dynamic");
    };
    assert_eq!(dynamic.ehdr().file_type(), ElfFileType::DYN);
    assert!(
        dynamic
            .phdrs()
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
    );

    let ScannedElf::StaticExec(exec) = LOADER
        .scan(ElfBinary::new("static_exec", static_exec()))
        .expect("scan should accept static executable metadata")
    else {
        panic!("executable without PT_DYNAMIC should scan as static exec");
    };
    assert_eq!(exec.ehdr().file_type(), ElfFileType::EXEC);
    assert!(
        exec.phdrs()
            .iter()
            .all(|phdr| phdr.program_type() != ElfProgramType::DYNAMIC)
    );
}
