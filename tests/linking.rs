use elf_loader::{
    Loader,
    arch::{
        REL_COPY, REL_DTPMOD, REL_DTPOFF, REL_GOT, REL_IRELATIVE, REL_JUMP_SLOT, REL_RELATIVE,
        REL_SYMBOLIC,
    },
    input::ElfBinary,
};
use gen_elf::{Arch, DylibWriter, ElfWriterConfig, ObjectWriter, RelocEntry, SymbolDesc};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::thread;

const EXTERNAL_FUNC_NAME: &str = "external_func";
const EXTERNAL_FUNC_NAME2: &str = "external_func2";
const EXTERNAL_VAR_NAME: &str = "external_var";
const EXTERNAL_TLS_NAME: &str = "external_tls";
const EXTERNAL_TLS_NAME2: &str = "external_tls2";
const COPY_VAR_NAME: &str = "copy_var";
const LOCAL_VAR_NAME: &str = "local_var";

const IFUNC_RESOLVER_VALUE: u64 = 100;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct F64x2(pub [f64; 2]);

#[unsafe(no_mangle)]
// External function and variables to be resolved
extern "C" fn external_func(
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
    a6: i64,
    a7: i64,
    a8: i64,
    v1: F64x2,
    f1: f64,
    f2: f64,
    f3: f64,
    f4: f64,
    f5: f64,
    f6: f64,
    f7: f64,
) -> f64 {
    (a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8) as f64
        + (f1 + f2 + f3 + f4 + f5 + f6 + f7)
        + v1.0[0]
        + v1.0[1]
}

type ExternalFunc = extern "C" fn(
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    F64x2,
    f64,
    f64,
    f64,
    f64,
    f64,
    f64,
    f64,
) -> f64;

type TlsHelperFunc = extern "C" fn() -> *mut u32;

static mut EXTERNAL_VAR: i32 = 100;

pub unsafe fn read_u64(p: *const u8) -> u64 {
    unsafe { (p as *const u64).read_unaligned() }
}

pub unsafe fn read_i32(p: *const u8) -> i32 {
    unsafe { (p as *const i32).read_unaligned() }
}

pub fn get_symbol_lookup() -> (
    HashMap<&'static str, usize>,
    Arc<dyn Fn(&str) -> Option<*const ()> + Send + Sync>,
) {
    let symbol_map = HashMap::from([
        (EXTERNAL_FUNC_NAME, external_func as *const () as usize),
        (EXTERNAL_FUNC_NAME2, external_func as *const () as usize),
        (EXTERNAL_VAR_NAME, &raw const EXTERNAL_VAR as usize),
    ]);

    let symbol_lookup_map = symbol_map.clone();
    let symbol_lookup =
        Arc::new(move |name: &str| symbol_lookup_map.get(name).map(|&addr| addr as *const ()));

    (symbol_map, symbol_lookup)
}

fn get_relocs_dynamic() -> Vec<RelocEntry> {
    vec![
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, REL_JUMP_SLOT),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME2, REL_JUMP_SLOT),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, REL_GOT),
        RelocEntry::with_name(LOCAL_VAR_NAME, REL_SYMBOLIC),
        RelocEntry::with_name(COPY_VAR_NAME, REL_COPY),
        RelocEntry::with_name(EXTERNAL_TLS_NAME, REL_DTPMOD),
        RelocEntry::with_name(EXTERNAL_TLS_NAME, REL_DTPOFF),
        RelocEntry::with_name(EXTERNAL_TLS_NAME2, REL_DTPMOD),
        RelocEntry::with_name(EXTERNAL_TLS_NAME2, REL_DTPOFF),
        RelocEntry::new(REL_RELATIVE),
        RelocEntry::new(REL_IRELATIVE),
    ]
}

#[test]
fn dynamic_linking() {
    run_dynamic_linking(false);
}

#[test]
fn dynamic_linking_with_lazy() {
    run_dynamic_linking(true);
}

fn run_dynamic_linking(is_lazy: bool) {
    let arch = Arch::current();
    let config = ElfWriterConfig::default().with_ifunc_resolver_val(IFUNC_RESOLVER_VALUE);

    // 1. Generate helper library
    let helper_output = DylibWriter::with_config(arch, config.clone())
        .write(
            &[],
            &[
                SymbolDesc::global_object(
                    COPY_VAR_NAME,
                    &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                ),
                SymbolDesc::global_tls(EXTERNAL_TLS_NAME, &[0xAA, 0xBB, 0xCC, 0xDD]),
                SymbolDesc::global_tls(EXTERNAL_TLS_NAME2, &[0x11, 0x22, 0x33, 0x44]),
            ],
        )
        .expect("Failed to generate helper ELF");

    // 2. Generate main dynamic library
    let elf_output = DylibWriter::with_config(arch, config)
        .write(
            &get_relocs_dynamic(),
            &[
                SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 8]),
                SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
                SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME2),
                SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
                SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME),
                SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME2),
                SymbolDesc::undefined_object(COPY_VAR_NAME).with_size(8),
            ],
        )
        .expect("Failed to generate ELF");

    let test_name = if is_lazy { "Lazy" } else { "Standard" };
    println!("Testing {} Linking on {:?}", test_name, arch);

    let (symbol_map, symbol_lookup) = get_symbol_lookup();

    // Load the dynamic library
    let mut loader = Loader::new();
    let helper_relocated = loader
        .load_dylib(ElfBinary::new("libhelper.so", &helper_output.data))
        .expect("Failed to load helper")
        .relocator()
        .relocate()
        .expect("Failed to relocate helper");

    let dylib = loader
        .load_dylib(ElfBinary::new("test_dynamic.so", &elf_output.data))
        .expect("Failed to load dylib");

    let relocator = dylib
        .relocator()
        .pre_find(symbol_lookup.clone())
        .scope(&[helper_relocated.clone()])
        .lazy(is_lazy);

    let relocated = if is_lazy {
        relocator.lazy_scope(symbol_lookup.clone()).relocate()
    } else {
        relocator.relocate()
    }
    .expect("Failed to relocate");

    let v_val = F64x2([9.9, 10.10]);
    let expected = (1..9).sum::<i64>() as f64
        + (1..8).map(|i| i as f64 + i as f64 / 10.0).sum::<f64>()
        + v_val.0[0]
        + v_val.0[1];

    assert!(
        (external_func(
            1, 2, 3, 4, 5, 6, 7, 8, v_val, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7
        ) - expected)
            .abs()
            < 0.0001
    );

    let helper_name = format!("{}@plt_helper", EXTERNAL_FUNC_NAME);
    unsafe {
        let helper_func: ExternalFunc =
            core::mem::transmute(relocated.get::<*const ()>(&helper_name).unwrap().into_raw());
        assert!(
            (helper_func(
                1, 2, 3, 4, 5, 6, 7, 8, v_val, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7
            ) - expected)
                .abs()
                < 0.0001
        );
    }

    // Verify relocation entries
    let actual_base = relocated.base();
    for reloc_info in &elf_output.relocations {
        let real_addr = actual_base + reloc_info.vaddr as usize;
        unsafe {
            let actual_value = if cfg!(target_pointer_width = "64") {
                *(real_addr as *const u64)
            } else {
                *(real_addr as *const u32) as u64
            };

            match reloc_info.r_type {
                REL_SYMBOLIC | REL_GOT | REL_JUMP_SLOT | REL_COPY => {
                    let (_, sym) = relocated.symtab().symbol_idx(reloc_info.sym_idx as usize);
                    let name = sym.name();
                    if name == "__tls_get_addr" {
                        continue;
                    }

                    let s = symbol_map
                        .get(name)
                        .map(|&a| a as u64)
                        .or_else(|| {
                            relocated
                                .get::<*const ()>(name)
                                .map(|s| s.into_raw() as u64)
                        })
                        .unwrap_or(0);

                    if reloc_info.r_type == REL_JUMP_SLOT && is_lazy {
                    } else if reloc_info.r_type == REL_COPY {
                        let src = helper_relocated.get::<*const u8>(name).unwrap().into_raw();
                        assert_eq!(
                            std::slice::from_raw_parts(
                                src as *const u8,
                                reloc_info.sym_size as usize
                            ),
                            std::slice::from_raw_parts(
                                real_addr as *const u8,
                                reloc_info.sym_size as usize
                            )
                        );
                    } else {
                        let expected = if reloc_info.r_type == REL_SYMBOLIC {
                            s.wrapping_add(reloc_info.addend as u64)
                        } else {
                            s
                        };
                        assert_eq!(actual_value, expected, "Mismatch for {}", name);
                    }
                }
                REL_DTPMOD => {
                    assert!(actual_value == helper_relocated.tls_mod_id().unwrap() as u64);
                }
                REL_DTPOFF => {
                    let (_, sym) = relocated.symtab().symbol_idx(reloc_info.sym_idx as usize);
                    let name = sym.name();
                    let st_value = relocated
                        .get::<()>(name)
                        .map(|s| s.into_raw() as usize - relocated.base())
                        .or_else(|| {
                            helper_relocated
                                .get::<()>(name)
                                .map(|s| s.into_raw() as usize - helper_relocated.base())
                        })
                        .unwrap_or(0);
                    let expected = (st_value as u64)
                        .wrapping_add(reloc_info.addend as u64)
                        .wrapping_sub(elf_loader::arch::TLS_DTV_OFFSET as u64);
                    assert_eq!(actual_value, expected, "DTPOFF mismatch for {}", name);
                }
                REL_RELATIVE => assert_eq!(
                    actual_value,
                    (actual_base as i64 + reloc_info.addend) as u64
                ),
                REL_IRELATIVE => {
                    assert_eq!(actual_value, actual_base as u64 + IFUNC_RESOLVER_VALUE)
                }
                _ => panic!("Unknown relocation type: {}", reloc_info.r_type),
            }
        }
    }

    // TLS Multi-threaded Test
    let tls1_helper: TlsHelperFunc = unsafe {
        core::mem::transmute(
            relocated
                .get::<*const ()>(&format!("{}@tls_helper", EXTERNAL_TLS_NAME))
                .unwrap()
                .into_raw(),
        )
    };
    let tls2_helper: TlsHelperFunc = unsafe {
        core::mem::transmute(
            relocated
                .get::<*const ()>(&format!("{}@tls_helper", EXTERNAL_TLS_NAME2))
                .unwrap()
                .into_raw(),
        )
    };

    let num_threads = 4;
    let barrier = Arc::new(Barrier::new(num_threads));
    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let b = barrier.clone();
            thread::spawn(move || {
                let (p1, p2) = (tls1_helper(), tls2_helper());
                unsafe {
                    assert_eq!(*p1, 0xDDCCBBAA);
                    assert_eq!(*p2, 0x44332211);
                    b.wait();
                    (*p1, *p2) = (i as u32 + 0x100, i as u32 + 0x200);
                    b.wait();
                    assert_eq!((*p1, *p2), (i as u32 + 0x100, i as u32 + 0x200));
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
    println!("✓ {} linking test passed", test_name);
}

#[test]
fn static_linking() {
    let arch = Arch::current();
    if arch != Arch::X86_64 {
        println!("Skipping static linking test for {:?}", arch);
        return;
    }

    let symbols = vec![
        SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x100]),
        SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
        SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
        SymbolDesc::undefined_object(EXTERNAL_TLS_NAME),
    ];

    let relocs = vec![
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 1), // R_X86_64_64
        RelocEntry::with_name(EXTERNAL_VAR_NAME, 9),  // R_X86_64_GOTPCREL
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 9), // R_X86_64_GOTPCREL
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, 4), // R_X86_64_PLT32
        RelocEntry::new(1),                           // R_X86_64_64
        RelocEntry::with_name(EXTERNAL_VAR_NAME, 1),  // R_X86_64_64
    ];

    let output = ObjectWriter::new(arch)
        .write(&symbols, &relocs)
        .expect("Failed to generate static ELF");
    let (symbol_map, symbol_lookup) = get_symbol_lookup();

    let relocated = Loader::new()
        .load_object(ElfBinary::new("test_static.o", &output.data))
        .expect("Failed to load object")
        .relocator()
        .pre_find(symbol_lookup)
        .relocate()
        .expect("Relocation failed");

    let data_base = unsafe { relocated.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let ext_func = symbol_map[EXTERNAL_FUNC_NAME];
    let ext_var = symbol_map[EXTERNAL_VAR_NAME];

    println!("Testing Static Linking on {:?}", arch);

    let check = |off: u64, expected: usize, msg: &str| {
        let p = (data_base + off as usize) as *const u8;
        let val = unsafe { read_u64(p) } as usize;
        assert_eq!(val, expected, "{}", msg);
    };

    let check_rel = |off: u64, expected: usize, msg: &str| {
        let p = (data_base + off as usize) as *const u8;
        let target = (p as usize).wrapping_add(unsafe { read_i32(p) } as usize);
        let val = unsafe { read_u64(target as *const u8) } as usize;
        assert_eq!(val, expected, "{}", msg);
    };

    check(
        output.reloc_offsets[0],
        ext_func,
        "R_X86_64_64 func mismatch",
    );
    check_rel(
        output.reloc_offsets[1],
        ext_var,
        "R_X86_64_GOTPCREL var mismatch",
    );
    check_rel(
        output.reloc_offsets[2],
        ext_func,
        "R_X86_64_GOTPCREL func mismatch",
    );

    // PLT check
    let p = (data_base + output.reloc_offsets[3] as usize) as *const u8;
    let target = (p as usize).wrapping_add(unsafe { read_i32(p) } as usize);
    if target != ext_func {
        assert_eq!(
            unsafe { read_u64(target as *const u8) } & 0xffffffff,
            0xfa1e0ff3,
            "PLT signature mismatch"
        );
    }

    check(
        output.reloc_offsets[4],
        data_base,
        "R_X86_64_64 relative mismatch",
    );
    check(
        output.reloc_offsets[5],
        ext_var,
        "R_X86_64_64 absolute mismatch",
    );

    println!("✓ Static linking test passed");
}
