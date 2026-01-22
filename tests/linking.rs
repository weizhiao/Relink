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

pub fn get_symbol_lookup() -> (
    HashMap<&'static str, usize>,
    Arc<dyn Fn(&str) -> Option<*const ()> + Send + Sync>,
) {
    let mut symbol_map = HashMap::new();
    symbol_map.insert(EXTERNAL_FUNC_NAME, external_func as usize);
    symbol_map.insert(EXTERNAL_FUNC_NAME2, external_func as usize);
    symbol_map.insert(EXTERNAL_VAR_NAME, &raw const EXTERNAL_VAR as usize);

    let symbol_lookup_map = symbol_map.clone();
    let symbol_lookup = Arc::new(move |name: &str| -> Option<*const ()> {
        symbol_lookup_map.get(name).map(|&addr| addr as *const ())
    });

    (symbol_map, symbol_lookup)
}

pub unsafe fn read_u64(p: *const u8) -> u64 {
    let mut b = [0u8; 8];
    unsafe { core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 8) };
    u64::from_le_bytes(b)
}

pub unsafe fn read_i32(p: *const u8) -> i32 {
    let mut b = [0u8; 4];
    unsafe { core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 4) };
    i32::from_le_bytes(b)
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
    // 1. Generate helper library that defines the symbol to be copied
    let config = ElfWriterConfig::default().with_ifunc_resolver_val(IFUNC_RESOLVER_VALUE);
    let helper_writer = DylibWriter::with_config(arch, config.clone());
    let helper_symbols = vec![
        SymbolDesc::global_object(
            COPY_VAR_NAME,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ),
        SymbolDesc::global_tls(EXTERNAL_TLS_NAME, &[0xAA, 0xBB, 0xCC, 0xDD]),
        SymbolDesc::global_tls(EXTERNAL_TLS_NAME2, &[0x11, 0x22, 0x33, 0x44]),
    ];
    let helper_output = helper_writer
        .write(&[], &helper_symbols)
        .expect("Failed to generate helper ELF");

    // 2. Generate main dynamic library with COPY relocation
    let writer = DylibWriter::with_config(arch, config);
    let relocs = get_relocs_dynamic();
    let symbols = vec![
        SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 8]),
        SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
        SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME2),
        SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
        SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME),
        SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME2),
        SymbolDesc::undefined_object(COPY_VAR_NAME).with_size(8),
    ];

    let elf_output = writer
        .write(&relocs, &symbols)
        .expect("Failed to generate ELF");

    let test_name = if is_lazy {
        "Lazy Binding"
    } else {
        "Standard Binding"
    };
    println!("\n--- {} Test ---", test_name);

    // Save the ELF to a file for inspection
    std::fs::write("/tmp/test_dynamic.so", &elf_output.data).expect("Failed to write ELF to file");
    std::fs::write("/tmp/helper.so", &helper_output.data)
        .expect("Failed to write helper ELF to file");

    let (symbol_map, symbol_lookup) = get_symbol_lookup();

    // Create ElfBinary from generated bytes
    let helper_binary = ElfBinary::new("libhelper.so", &helper_output.data);
    let elf_binary = ElfBinary::new("test_dynamic.so", &elf_output.data);

    // Load the dynamic library
    let mut loader = Loader::new();
    let helper_lib = loader
        .load_dylib(helper_binary)
        .expect("Failed to load helper library");
    let helper_relocated = helper_lib
        .relocator()
        .relocate()
        .expect("Failed to relocate helper library");

    let dylib = loader
        .load_dylib(elf_binary)
        .expect("Failed to load dynamic library");

    // Relocate the library with symbol resolution
    let scope = [helper_relocated.clone()];
    let relocator = dylib
        .relocator()
        .pre_find(symbol_lookup.clone())
        .scope(&scope)
        .lazy(is_lazy);

    let relocated = if is_lazy {
        relocator.lazy_scope(symbol_lookup.clone()).relocate()
    } else {
        relocator.relocate()
    }
    .expect("Failed to relocate dynamic library");

    println!("✓ Library loaded and relocated at 0x{:x}", relocated.base());

    let v_val = F64x2([9.9, 10.10]);

    let result = external_func(
        1, 2, 3, 4, 5, 6, 7, 8, v_val, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7,
    );
    let expected = (1 + 2 + 3 + 4 + 5 + 6 + 7 + 8) as f64
        + (1.1 + 2.2 + 3.3 + 4.4 + 5.5 + 6.6 + 7.7)
        + v_val.0[0]
        + v_val.0[1];
    assert!((result - expected).abs() < 0.0001);
    println!("✓ Direct call verified");

    let helper_name = format!("{}@plt_helper", EXTERNAL_FUNC_NAME);
    unsafe {
        let helper_func: ExternalFunc = core::mem::transmute(
            relocated
                .get::<*const ()>(&helper_name)
                .expect("Failed to get helper function")
                .into_raw(),
        );

        let result = helper_func(
            1, 2, 3, 4, 5, 6, 7, 8, v_val, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7,
        );
        assert!((result - expected).abs() < 0.0001);
    }
    println!("✓ Binding verified via helper function with many arguments");

    // Verify relocation entries comprehensively
    let mut reloc_by_type: HashMap<u32, usize> = HashMap::new();
    for reloc_info in &elf_output.relocations {
        *reloc_by_type.entry(reloc_info.r_type).or_insert(0) += 1;
    }

    // Get the actual base address where the library was loaded
    let actual_base = relocated.base();

    for reloc_info in &elf_output.relocations {
        // Calculate the real address in loaded memory
        let real_addr = actual_base + reloc_info.vaddr as usize;

        // Read and verify the value at the relocation address
        unsafe {
            let actual_value = if cfg!(target_pointer_width = "64") {
                *(real_addr as *const u64)
            } else {
                *(real_addr as *const u32) as u64
            };

            // Calculate expected value based on relocation type
            match reloc_info.r_type {
                REL_SYMBOLIC | REL_GOT | REL_JUMP_SLOT | REL_COPY => {
                    let (_, sym_info) = relocated.symtab().symbol_idx(reloc_info.sym_idx as usize);
                    let sym_name = sym_info.name();

                    if sym_name == "__tls_get_addr" {
                        continue;
                    }

                    let s = if let Some(addr) = symbol_map.get(sym_name) {
                        *addr as u64
                    } else {
                        // If not in external symbol map, it might be internal
                        relocated
                            .get::<*const ()>(sym_name)
                            .map(|s| s.into_raw() as u64)
                            .unwrap_or(0)
                    };

                    if reloc_info.r_type == REL_JUMP_SLOT && is_lazy {
                        // With lazy binding, JUMP_SLOT points to PLT stub
                        // No check needed here as it will be resolved lazily
                    } else if reloc_info.r_type == REL_COPY {
                        // For COPY relocation, verify the data was copied from helper_relocated
                        let symbol = helper_relocated
                            .get::<*const u8>(sym_name)
                            .expect("Symbol not found in helper");
                        let src_addr = symbol.into_raw();
                        let size = reloc_info.sym_size as usize;
                        let src_data = std::slice::from_raw_parts(src_addr as *const u8, size);
                        let dest_data = std::slice::from_raw_parts(real_addr as *const u8, size);
                        assert_eq!(
                            src_data, dest_data,
                            "    ✗ COPY data mismatch! Expected {:?}, got {:?}",
                            src_data, dest_data
                        );
                    } else {
                        let expected_value = if reloc_info.r_type == REL_SYMBOLIC {
                            s.wrapping_add(reloc_info.addend as u64)
                        } else {
                            s
                        };
                        assert!(
                            actual_value == expected_value,
                            "    ✗ Value mismatch! Expected 0x{:x}, got 0x{:x}",
                            expected_value,
                            actual_value
                        );
                    }
                }
                REL_DTPMOD => {
                    assert!(
                        actual_value > 0,
                        "    ✗ DTPMOD must be greater than 0, got 0"
                    );
                }
                REL_DTPOFF => {
                    let (_, name_info) = relocated.symtab().symbol_idx(reloc_info.sym_idx as usize);
                    let name = name_info.name();
                    let mut expected_st_value = 0;
                    for dep in &scope {
                        if let Some(symbol) = dep.get::<()>(name) {
                            expected_st_value = symbol.into_raw() as usize - dep.base();
                            break;
                        }
                    }
                    let expected_value =
                        (expected_st_value as u64).wrapping_add(reloc_info.addend as u64);
                    let expected_value =
                        expected_value.wrapping_sub(elf_loader::arch::TLS_DTV_OFFSET as u64);
                    assert_eq!(
                        actual_value, expected_value,
                        "    ✗ DTPOFF mismatch for {}! Expected 0x{:x}, got 0x{:x}",
                        name, expected_value, actual_value
                    );
                }
                REL_RELATIVE => {
                    let expected_value = (actual_base as i64 + reloc_info.addend) as u64;
                    assert!(
                        actual_value == expected_value,
                        "    ✗ Relative mismatch! Expected 0x{:x}, got 0x{:x}",
                        expected_value,
                        actual_value
                    );
                }
                REL_IRELATIVE => {
                    // For IRELATIVE, the value should be the result of the resolver
                    // In gen_relocs, the resolver returns plt_vaddr (PLT[0]) or a custom value
                    // Since the resolver is PIC, it returns (actual_base + value)
                    let expected_value = actual_base as u64 + IFUNC_RESOLVER_VALUE;
                    assert!(
                        actual_value == expected_value,
                        "    ✗ IRELATIVE resolver value mismatch! Expected 0x{:x}, got 0x{:x}",
                        expected_value,
                        actual_value
                    );
                }
                _ => {
                    panic!("    ✗ Unknown type, value present: 0x{:x}", actual_value);
                }
            }
        }
    }
    println!(
        "✓ All {} relocations verified",
        elf_output.relocations.len()
    );

    // 4. TLS Multi-threaded Test
    println!("✓ Starting TLS multi-threaded test");
    let tls1_helper_name = format!("{}@tls_helper", EXTERNAL_TLS_NAME);
    let tls2_helper_name = format!("{}@tls_helper", EXTERNAL_TLS_NAME2);

    let tls1_helper_addr = unsafe {
        relocated
            .get::<*const ()>(&tls1_helper_name)
            .expect("Failed to get TLS 1 helper")
            .into_raw()
    };
    let tls2_helper_addr = unsafe {
        relocated
            .get::<*const ()>(&tls2_helper_name)
            .expect("Failed to get TLS 2 helper")
            .into_raw()
    };

    let tls1_helper: TlsHelperFunc = unsafe { core::mem::transmute(tls1_helper_addr) };
    let tls2_helper: TlsHelperFunc = unsafe { core::mem::transmute(tls2_helper_addr) };

    let num_threads = 4;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];

    for i in 0..num_threads {
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            let p1 = tls1_helper();
            let p2 = tls2_helper();

            println!("Thread {}: p1={:p}, p2={:p}", i, p1, p2);

            // Verify initial values from helper.so
            // libhelper.so:
            //   EXTERNAL_TLS_NAME:  [0xAA, 0xBB, 0xCC, 0xDD] -> 0xDDCCBBAA
            //   EXTERNAL_TLS_NAME2: [0x11, 0x22, 0x33, 0x44] -> 0x44332211
            unsafe {
                if p1.is_null() || p2.is_null() {
                    panic!("TLS pointer is NULL");
                }
                assert!((p1 as usize) % 4 == 0, "p1 is misaligned: {:p}", p1);
                assert!((p2 as usize) % 4 == 0, "p2 is misaligned: {:p}", p2);
                assert_eq!(*p1, 0xDDCCBBAA);
                assert_eq!(*p2, 0x44332211);
            }

            // Sync threads
            b.wait();

            // Modify values uniquely to this thread
            unsafe {
                *p1 = (i as u32) + 0x100;
                *p2 = (i as u32) + 0x200;
            }

            // Sync threads again to ensure all have modified their local storage
            b.wait();

            // Verify values are still what this thread set (no crosstalk)
            unsafe {
                assert_eq!(*p1, (i as u32) + 0x100);
                assert_eq!(*p2, (i as u32) + 0x200);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked during TLS test");
    }
    println!("✓ TLS multi-threaded test passed");
}

#[test]
fn static_linking() {
    let arch = Arch::current();

    // Define symbols
    let symbols = vec![
        SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x100]), // 0x100 bytes of data
        SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
        SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
        SymbolDesc::undefined_object(EXTERNAL_TLS_NAME),
    ];

    // Define relocations for x86_64
    let relocs = match arch {
        Arch::X86_64 => vec![
            RelocEntry::with_name(EXTERNAL_FUNC_NAME, 1), // R_X86_64_64
            RelocEntry::with_name(EXTERNAL_VAR_NAME, 9),  // R_X86_64_GOTPCREL
            RelocEntry::with_name(EXTERNAL_FUNC_NAME, 9), // R_X86_64_GOTPCREL
            RelocEntry::with_name(EXTERNAL_FUNC_NAME, 4), // R_X86_64_PLT32
            RelocEntry::new(1),                           // R_X86_64_64
            RelocEntry::with_name(EXTERNAL_VAR_NAME, 1),  // R_X86_64_64
        ],
        _ => {
            println!("Skipping test for unsupported architecture: {:?}", arch);
            return;
        }
    };

    let output = ObjectWriter::new(arch)
        .write(&symbols, &relocs)
        .expect("Failed to generate static ELF");
    let elf_data = &output.data;
    let reloc_offsets = &output.reloc_offsets;

    let (symbol_map, symbol_lookup) = get_symbol_lookup();

    // Create ElfBinary from generated bytes
    let elf_binary = ElfBinary::new("test_static.o", &elf_data);
    println!("ElfBinary created, size: {}", elf_data.len());

    // Write to file for debugging
    std::fs::write("/tmp/test_static.o", &elf_data).expect("Failed to write ELF to file");

    // Load the relocatable object
    let mut loader = Loader::new();
    let obj = loader
        .load_object(elf_binary)
        .expect("Failed to load relocatable object");
    println!("Relocatable object loaded");

    // Relocate the object with symbol resolution
    let relocated = obj
        .relocator()
        .pre_find(symbol_lookup.clone())
        .relocate()
        .expect("Failed to relocate");
    println!("Relocation completed");

    println!("Relocated object base: {:?}", relocated.base());

    // Locate the base of the .data section via the `local_var` symbol
    let local_ptr = unsafe {
        relocated
            .get::<i32>(LOCAL_VAR_NAME)
            .expect("missing `local_var` in relocated object")
    };
    let local_addr = local_ptr.into_raw() as usize;
    println!("local_var addr: {:#x}", local_addr);
    // In gen_static_elf, local_var is at offset 0 in its section
    let data_base = local_addr;
    println!("data_base: {:#x}", data_base);

    let external_func_addr = symbol_map.get(EXTERNAL_FUNC_NAME).copied().unwrap() as usize;
    let external_var_addr = symbol_map.get(EXTERNAL_VAR_NAME).copied().unwrap() as usize;

    // Verify relocations
    if arch == Arch::X86_64 {
        // reloc_offsets[0]: R_X86_64_64 -> external_func
        {
            let addr = (data_base + reloc_offsets[0] as usize) as *const u8;
            let val = unsafe { read_u64(addr) } as usize;
            assert_eq!(val, external_func_addr, "reloc_offsets[0] mismatch");
        }

        // reloc_offsets[1]: R_X86_64_GOTPCREL -> GOT entry - P
        {
            let p = (data_base + reloc_offsets[1] as usize) as *const u8;
            let val = unsafe { read_i32(p) };
            let target = (p as usize).wrapping_add(val as usize);
            let got_val = unsafe { read_u64(target as *const u8) } as usize;
            assert_eq!(got_val, external_var_addr, "reloc_offsets[1] mismatch");
        }

        // reloc_offsets[2]: R_X86_64_GOTPCREL -> GOT entry - P
        {
            let p = (data_base + reloc_offsets[2] as usize) as *const u8;
            let val = unsafe { read_i32(p) };
            let target = (p as usize).wrapping_add(val as usize);
            let got_val = unsafe { read_u64(target as *const u8) } as usize;
            assert_eq!(got_val, external_func_addr, "reloc_offsets[2] mismatch");
        }

        // reloc_offsets[3]: R_X86_64_PLT32 -> PLT entry - P
        {
            let p = (data_base + reloc_offsets[3] as usize) as *const u8;
            let val = unsafe { read_i32(p) };
            let target = (p as usize).wrapping_add(val as usize);
            if target != external_func_addr {
                let code = unsafe { read_u64(target as *const u8) };
                assert_eq!(
                    code & 0xffffffff,
                    0xfa1e0ff3,
                    "reloc_offsets[3] signature mismatch"
                );
            }
        }

        // reloc_offsets[4]: R_X86_64_64 (Relative-like) -> data_base
        {
            let addr = (data_base + reloc_offsets[4] as usize) as *const u8;
            let val = unsafe { read_u64(addr) } as usize;
            assert_eq!(val, data_base, "reloc_offsets[4] mismatch");
        }

        // reloc_offsets[5]: R_X86_64_64 (TLS-like) -> external_var
        {
            let addr = (data_base + reloc_offsets[5] as usize) as *const u8;
            let val = unsafe { read_u64(addr) } as usize;
            assert_eq!(val, external_var_addr, "reloc_offsets[5] mismatch");
        }
    }
}
