use elf_loader::{
    Module, Relocator,
    image::{SyntheticModule, SyntheticSymbol},
};
use gen_elf::{ObjectElfOutput, RelocationInfo, SectionKind};

const EXTERNAL_FUNC_NAME: &str = "external_func";
const EXTERNAL_FUNC_NAME2: &str = "external_func2";
const EXTERNAL_VAR_NAME: &str = "external_var";

#[repr(C)]
struct F64Pair([f64; 2]);

#[unsafe(no_mangle)]
extern "C" fn external_func(
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
    a6: i64,
    a7: i64,
    a8: i64,
    vector: F64Pair,
    f1: f64,
    f2: f64,
    f3: f64,
    f4: f64,
    f5: f64,
    f6: f64,
    f7: f64,
) -> f64 {
    (a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8) as f64
        + f1
        + f2
        + f3
        + f4
        + f5
        + f6
        + f7
        + vector.0[0]
        + vector.0[1]
}

static mut EXTERNAL_VAR: i32 = 100;

struct HostSymbols {
    func: usize,
    var: usize,
}

impl HostSymbols {
    fn new() -> Self {
        Self {
            func: external_func as *const () as usize,
            var: &raw const EXTERNAL_VAR as usize,
        }
    }

    fn module(&self) -> SyntheticModule {
        let mut module = SyntheticModule::empty("__host");
        for name in [EXTERNAL_FUNC_NAME, EXTERNAL_FUNC_NAME2] {
            let _ = module.insert(SyntheticSymbol::function(name, self.func as *const ()));
        }
        let _ = module.insert(SyntheticSymbol::object(
            EXTERNAL_VAR_NAME,
            self.var as *const (),
            0,
        ));
        module
    }
}

fn relocation_for_symbol<'a>(
    output: &'a ObjectElfOutput,
    r_type: u32,
    symbol_name: &str,
) -> &'a RelocationInfo {
    output
        .find_relocation(r_type, symbol_name)
        .unwrap_or_else(|| {
            panic!(
                "missing relocation type {} for symbol {}",
                r_type, symbol_name
            )
        })
}

fn anonymous_relocation(output: &ObjectElfOutput, r_type: u32) -> &RelocationInfo {
    output
        .relocations
        .iter()
        .find(|reloc| reloc.r_type == r_type && reloc.symbol_name.is_none())
        .unwrap_or_else(|| panic!("missing relocation type {} without symbol", r_type))
}

fn read_u64(ptr: *const u8) -> u64 {
    unsafe { (ptr as *const u64).read_unaligned() }
}

fn read_i32(ptr: *const u8) -> i32 {
    unsafe { (ptr as *const i32).read_unaligned() }
}

#[test]
fn relocations_match() {
    use crate::LOCAL_VAR_NAME;
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};

    let arch = Arch::current();
    debug_assert_eq!(arch, Arch::X86_64);

    let symbols = vec![
        SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x100]),
        SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
        SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
    ];

    let relocs = vec![
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 1),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, 9),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 9),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 4),
        RelocEntry::new(1),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, 1),
    ];

    let object_file = ObjectWriter::new(arch)
        .write(&symbols, &relocs)
        .expect("failed to generate static ELF");
    let host_symbols = HostSymbols::new();

    let loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .load_object(elf_loader::input::ElfBinary::new(
                    "test_static.o",
                    &object_file.data,
                ))
                .expect("failed to load object"),
        )
        .modules([host_symbols.module()])
        .relocate()
        .expect("relocation failed");
    assert!(loaded_object.state().is_initialized());

    let data_base =
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let external_func_addr = host_symbols.func;
    let external_var_addr = host_symbols.var;

    let assert_absolute_slot = |relocation: &RelocationInfo, expected: usize, message: &str| {
        assert_eq!(relocation.section, SectionKind::Data);
        let slot = (data_base + relocation.offset as usize) as *const u8;
        let actual = read_u64(slot) as usize;
        assert_eq!(actual, expected, "{message}");
    };

    let assert_gotpcrel_target = |relocation: &RelocationInfo, expected: usize, message: &str| {
        assert_eq!(relocation.section, SectionKind::Data);
        let slot = (data_base + relocation.offset as usize) as *const u8;
        let target = (slot as usize).wrapping_add(read_i32(slot) as usize);
        let actual = read_u64(target as *const u8) as usize;
        assert_eq!(actual, expected, "{message}");
    };

    assert_absolute_slot(
        relocation_for_symbol(&object_file, 1, EXTERNAL_FUNC_NAME),
        external_func_addr,
        "R_X86_64_64 func mismatch",
    );
    assert_gotpcrel_target(
        relocation_for_symbol(&object_file, 9, EXTERNAL_VAR_NAME),
        external_var_addr,
        "R_X86_64_GOTPCREL var mismatch",
    );
    assert_gotpcrel_target(
        relocation_for_symbol(&object_file, 9, EXTERNAL_FUNC_NAME),
        external_func_addr,
        "R_X86_64_GOTPCREL func mismatch",
    );

    let plt_relocation = relocation_for_symbol(&object_file, 4, EXTERNAL_FUNC_NAME);
    let slot = (data_base + plt_relocation.offset as usize) as *const u8;
    let target = (slot as usize).wrapping_add(read_i32(slot) as usize);
    if target != external_func_addr {
        assert_eq!(
            read_u64(target as *const u8) & 0xffffffff,
            0xfa1e0ff3,
            "PLT signature mismatch"
        );
    }

    assert_absolute_slot(
        anonymous_relocation(&object_file, 1),
        data_base,
        "R_X86_64_64 relative mismatch",
    );
    assert_absolute_slot(
        relocation_for_symbol(&object_file, 1, EXTERNAL_VAR_NAME),
        external_var_addr,
        "R_X86_64_64 absolute mismatch",
    );
}

#[test]
fn addends_apply() {
    use crate::LOCAL_VAR_NAME;
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};

    let arch = Arch::current();
    debug_assert_eq!(arch, Arch::X86_64);

    let object_file = ObjectWriter::new(arch)
        .write(
            &[
                SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40]),
                SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
            ],
            &[RelocEntry::with_name(EXTERNAL_VAR_NAME, 1).with_addend(0x20)],
        )
        .expect("failed to generate object with addend relocation");
    let host_symbols = HostSymbols::new();

    let loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .load_object(elf_loader::input::ElfBinary::new(
                    "test_static_addend.o",
                    &object_file.data,
                ))
                .expect("failed to load object"),
        )
        .modules([host_symbols.module()])
        .relocate()
        .expect("relocation failed");

    let data_base =
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let relocation = relocation_for_symbol(&object_file, 1, EXTERNAL_VAR_NAME);
    assert_eq!(relocation.section, SectionKind::Data);

    let actual = read_u64((data_base + relocation.offset as usize) as *const u8) as usize;
    let expected = host_symbols.var + relocation.addend as usize;
    assert_eq!(actual, expected, "R_X86_64_64 addend mismatch");
}

#[test]
fn retained_core_allows_relocation() {
    use crate::LOCAL_VAR_NAME;
    use elf_loader::image::SymbolLookup;
    use gen_elf::{Arch, ObjectWriter, SymbolDesc};

    let object_file = ObjectWriter::new(Arch::current())
        .write(
            &[SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40])],
            &[],
        )
        .expect("failed to generate object");

    let raw = elf_loader::Loader::new()
        .load_object(elf_loader::input::ElfBinary::new(
            "retained_core.o",
            &object_file.data,
        ))
        .expect("failed to load object");
    let retained_core = (*raw).clone();

    let _loaded = Relocator::new()
        .run(raw)
        .relocate()
        .expect("retaining the raw object core must not prevent export installation");
    assert!(
        retained_core
            .exports()
            .lookup(&mut SymbolLookup::new(LOCAL_VAR_NAME))
            .is_some()
    );
}
