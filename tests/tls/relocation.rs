use elf_loader::{
    Module, arch::NativeArch, elf::SymbolLookup, memory::VmAddr, relocation::RelocationArch,
};
use gen_elf::SectionKind;

use crate::support::{DTPMOD, DTPOFF, FIRST, SECOND, scenario};

#[test]
fn applies_dynamic_relocations() {
    let scenario = scenario();
    let provider = scenario.provider();
    let mod_id = provider
        .tls()
        .expect("provider should own TLS")
        .mod_id()
        .get() as u64;

    for name in [FIRST, SECOND] {
        let dtpmod = scenario.relocation(DTPMOD, name);
        assert_eq!(dtpmod.section, SectionKind::Got);
        assert_eq!(scenario.slot(dtpmod), mod_id);

        let dtpoff = scenario.relocation(DTPOFF, name);
        let exports = provider.exports();
        let mut lookup = SymbolLookup::new(name);
        let symbol = exports
            .lookup(&mut lookup)
            .unwrap_or_else(|| panic!("missing TLS symbol {name}"));
        let addend = isize::try_from(dtpoff.addend).expect("TLS addend should fit isize");
        let expected = VmAddr::new(symbol.st_value())
            .wrapping_add_signed(addend)
            .get()
            .wrapping_sub(NativeArch::TLS_DTV_OFFSET) as u64;
        assert_eq!(scenario.slot(dtpoff), expected);
    }
}
