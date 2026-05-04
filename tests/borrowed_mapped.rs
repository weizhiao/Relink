mod support;

use elf_loader::{Loader, input::ElfBinary};
use gen_elf::{Arch, SymbolDesc};
use support::{generated_dylib::return_42_stub, test_dylib::write_test_dylib};

#[test]
fn borrowed_dynamic_reuses_existing_mapping() {
    let arch = Arch::current();
    let output = write_test_dylib(
        &[],
        &[SymbolDesc::global_func("answer", &return_42_stub(arch))],
    );

    let mut owner_loader = Loader::new();
    let owner = owner_loader
        .load_dylib(ElfBinary::new("owner.so", &output.data))
        .expect("failed to map owner dylib");
    let owner_dynamic = owner.dynamic_ptr().expect("owner should have PT_DYNAMIC");

    let mut borrowed_loader = Loader::new();
    let borrowed = unsafe {
        borrowed_loader.load_mapped_dynamic(
            "borrowed-main",
            owner.base(),
            owner.phdrs().to_vec(),
            owner.entry(),
        )
    }
    .expect("failed to wrap borrowed mapping");

    assert_eq!(borrowed.name(), "borrowed-main");
    assert_eq!(borrowed.base(), owner.base());
    assert_eq!(borrowed.entry(), owner.entry());
    assert_eq!(borrowed.mapped_len(), owner.mapped_len());
    assert!(borrowed.contains_addr(owner.base()));
    assert_eq!(borrowed.dynamic_ptr(), Some(owner_dynamic));
    assert_eq!(borrowed.needed_libs(), owner.needed_libs());
}
