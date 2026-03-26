#![cfg(unix)]

mod support;

use gen_elf::{Arch, DylibWriter, RelocEntry, SymbolDesc};
use support::{
    generated_dylib::{generated_dylib_path, load_unix_library, return_42_stub},
    memory::read_native_word,
};

#[test]
fn plt_call_patches_got() {
    let arch = Arch::current();
    let generated_dylib = DylibWriter::new(arch)
        .write(
            &[
                RelocEntry::jump_slot("callee", arch),
                RelocEntry::irelative(arch),
            ],
            &[SymbolDesc::global_func("callee", &return_42_stub(arch))],
        )
        .expect("failed to generate ELF");

    let dylib_path = generated_dylib_path("generated_dylib", arch);
    std::fs::write(&dylib_path, &generated_dylib.data).expect("failed to write ELF to file");

    let library = unsafe { load_unix_library(&dylib_path) };
    let callee_abs_addr = unsafe {
        let func: libloading::Symbol<unsafe extern "C" fn() -> i32> = library
            .get(b"callee")
            .expect("failed to get callee function");
        let addr = *func as *const () as usize;
        let result = func();
        assert_eq!(result, 42, "direct call returned wrong value");
        addr
    };

    let resolver_abs_addr = unsafe {
        let func: libloading::Symbol<unsafe extern "C" fn() -> u64> = library
            .get(b"__ifunc_resolver")
            .expect("failed to get resolver");
        *func as *const () as u64
    };
    let load_bias = resolver_abs_addr - generated_dylib.text_vaddr;

    let jump_slot_relocation = generated_dylib
        .find_relocation(Arch::current().jump_slot_reloc(), "callee")
        .expect("failed to find PLT relocation");

    let got_entry_addr = (load_bias
        + jump_slot_relocation
            .vaddr
            .expect("dynamic relocation metadata should include a virtual address"))
        as usize;

    let got_value_before = read_native_word(got_entry_addr);
    let func: libloading::Symbol<extern "C" fn() -> i32> = unsafe {
        library
            .get(b"callee@plt_helper")
            .expect("failed to get helper function")
    };

    let result = func();
    assert_eq!(result, 42, "PLT call returned wrong value");
    let got_value_after = read_native_word(got_entry_addr);

    assert_eq!(
        got_value_after as usize, callee_abs_addr,
        "GOT entry should be updated to callee address"
    );
    assert!(
        got_value_before != got_value_after,
        "GOT entry should change after PLT call"
    );
}
