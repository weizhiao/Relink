mod support;

#[cfg(all(feature = "object", target_arch = "x86_64"))]
use gen_elf::{ObjectElfOutput, RelocationInfo, SectionKind};

#[cfg(all(feature = "object", target_arch = "x86_64"))]
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

#[cfg(all(feature = "object", target_arch = "x86_64"))]
fn anonymous_relocation(output: &ObjectElfOutput, r_type: u32) -> &RelocationInfo {
    output
        .relocations
        .iter()
        .find(|reloc| reloc.r_type == r_type && reloc.symbol_name.is_none())
        .unwrap_or_else(|| panic!("missing relocation type {} without symbol", r_type))
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
fn assert_data_section(reloc: &RelocationInfo) {
    assert_eq!(reloc.section, SectionKind::Data);
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_relocations_match() {
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};
    use support::{
        host_symbols::{EXTERNAL_FUNC_NAME, EXTERNAL_VAR_NAME, LOCAL_VAR_NAME, TestHostSymbols},
        memory::{read_i32, read_u64},
    };

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
    let host_symbols = TestHostSymbols::new();

    let loaded_object = elf_loader::Loader::new()
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .scope([host_symbols.source("__host")])
        .relocate()
        .expect("relocation failed");
    assert!(loaded_object.is_init());

    let data_base =
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let external_func_addr = host_symbols.addresses[EXTERNAL_FUNC_NAME];
    let external_var_addr = host_symbols.addresses[EXTERNAL_VAR_NAME];

    let assert_absolute_slot = |relocation: &RelocationInfo, expected: usize, message: &str| {
        assert_data_section(relocation);
        let slot = (data_base + relocation.offset as usize) as *const u8;
        let actual = read_u64(slot) as usize;
        assert_eq!(actual, expected, "{message}");
    };

    let assert_gotpcrel_target = |relocation: &RelocationInfo, expected: usize, message: &str| {
        assert_data_section(relocation);
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

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_addends_apply() {
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};
    use support::{
        host_symbols::{EXTERNAL_VAR_NAME, LOCAL_VAR_NAME, TestHostSymbols},
        memory::read_u64,
    };

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
    let host_symbols = TestHostSymbols::new();

    let loaded_object = elf_loader::Loader::new()
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static_addend.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .scope([host_symbols.source("__host")])
        .relocate()
        .expect("relocation failed");

    let data_base =
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME).unwrap().into_raw() } as usize;
    let relocation = relocation_for_symbol(&object_file, 1, EXTERNAL_VAR_NAME);
    assert_data_section(relocation);

    let actual = read_u64((data_base + relocation.offset as usize) as *const u8) as usize;
    let expected = host_symbols.addresses[EXTERNAL_VAR_NAME] + relocation.addend as usize;
    assert_eq!(actual, expected, "R_X86_64_64 addend mismatch");
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn retained_raw_object_core_rejects_relocation_without_panicking() {
    use gen_elf::{Arch, ObjectWriter, SymbolDesc};
    use support::host_symbols::LOCAL_VAR_NAME;

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
    let _retained_core = (*raw).clone();

    let err = raw
        .relocator()
        .relocate()
        .expect_err("retained raw object core should reject relocation");
    assert!(
        err.to_string()
            .contains("raw object core was retained before runtime exports were installed")
    );
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_exports_survive_init_symtab_metadata() {
    use elf_loader::{
        Result,
        elf::{ElfSectionId, ElfSectionType},
        observer::{
            LoadObserver, SectionGroup, SectionGroups, SectionLayoutEvent, SectionLifetime,
        },
        os::ProtFlags,
    };
    use gen_elf::{Arch, ObjectWriter, RelocEntry, SymbolDesc};
    use support::host_symbols::{EXTERNAL_VAR_NAME, LOCAL_VAR_NAME, TestHostSymbols};

    struct InitSymtabObserver {
        init_meta: SectionGroup,
    }

    impl LoadObserver for InitSymtabObserver {
        fn on_section_layout(&mut self, event: &mut SectionLayoutEvent<'_>) -> Result<()> {
            let ids = event.section_ids().collect::<Vec<_>>();
            for id in ids {
                if event.sections().section(id).section_type() != ElfSectionType::SYMTAB {
                    continue;
                }

                event.place(id, self.init_meta);
                event.place(
                    ElfSectionId::new(event.sections().section(id).sh_link() as usize),
                    self.init_meta,
                );
            }

            Ok(())
        }
    }

    let object_file = ObjectWriter::new(Arch::current())
        .write(
            &[
                SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40]),
                SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
            ],
            &[RelocEntry::with_name(EXTERNAL_VAR_NAME, 1)],
        )
        .expect("failed to generate object with init metadata");
    let host_symbols = TestHostSymbols::new();
    let mut groups = SectionGroups::default();
    let init_meta = groups.define(
        ProtFlags::PROT_READ,
        ProtFlags::PROT_READ,
        10,
        SectionLifetime::Init,
    );

    let loaded_object = elf_loader::Loader::new()
        .with_object_section_groups(groups)
        .with_observer(InitSymtabObserver { init_meta })
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static_init_symtab.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .scope([host_symbols.source("__host")])
        .relocate()
        .expect("relocation failed");

    assert!(loaded_object.is_init());
    assert!(
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME) }.is_some(),
        "runtime object exports should survive init metadata release"
    );
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_relocated_event_exposes_section_metadata() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        image::{LoadedCore, ModuleHandle},
        memory::{HostRegion, RegionAccess},
        observer::{LoadObserver, ObjectRelocatedEvent, RelocationObserver, SectionLayoutEvent},
        tls::TlsResolver,
    };
    use gen_elf::{Arch, ObjectWriter, SymbolDesc};
    use support::host_symbols::LOCAL_VAR_NAME;

    struct SkipShstrtab;

    impl LoadObserver for SkipShstrtab {
        fn on_section_layout(&mut self, event: &mut SectionLayoutEvent<'_>) -> Result<()> {
            let shstrtab = event
                .sections()
                .find_section(".shstrtab")
                .expect("generated object should contain .shstrtab");
            event.skip(shstrtab);
            Ok(())
        }
    }

    struct MetadataObserver;

    impl RelocationObserver for MetadataObserver {
        fn on_object_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver>(
            &mut self,
            event: &mut ObjectRelocatedEvent<'_, D, NativeArch, R, Tls>,
        ) -> Result<()> {
            let data = event
                .sections()
                .find_section(".data")
                .expect("generated object should contain .data");
            assert!(event.section_is_mapped(data));
            assert!(event.section_addr(data).is_some());
            assert!(event.section_host_ptr(data).is_some());
            assert_eq!(event.sections().section_name(data).to_bytes(), b".data");

            let symtab = event
                .sections()
                .find_section(".symtab")
                .expect("generated object should contain .symtab");
            assert!(event.section_is_mapped(symtab));

            let shstrtab = event
                .sections()
                .find_section(".shstrtab")
                .expect("generated object should contain .shstrtab");
            assert!(!event.section_is_mapped(shstrtab));
            assert!(event.section_addr(shstrtab).is_none());
            assert!(event.section_host_ptr(shstrtab).is_none());
            assert!(event.section_host_ptr_range(shstrtab, 1).is_none());
            Ok(())
        }
    }

    let object_file = ObjectWriter::new(Arch::current())
        .write(
            &[SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40])],
            &[],
        )
        .expect("failed to generate object");

    let loaded_object = elf_loader::Loader::new()
        .with_observer(SkipShstrtab)
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static_metadata.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .observer(MetadataObserver)
        .relocate()
        .expect("relocation failed");

    let handle: ModuleHandle = (&loaded_object).into();
    handle
        .downcast_ref::<LoadedCore<(), NativeArch, HostRegion>>()
        .expect("ModuleHandle should retain loaded core");
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_relocated_event_can_clear_default_exports() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        memory::{ImageMemory, RegionAccess, VmOffset},
        observer::{ObjectRelocatedEvent, RelocationObserver},
        tls::TlsResolver,
    };
    use gen_elf::{Arch, ObjectWriter, SymbolDesc};
    use support::host_symbols::LOCAL_VAR_NAME;

    struct ClearExports;

    impl RelocationObserver for ClearExports {
        fn on_object_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver>(
            &mut self,
            event: &mut ObjectRelocatedEvent<'_, D, NativeArch, R, Tls>,
        ) -> Result<()> {
            let symtab = event.symtab();
            assert!(
                (0..symtab.symbols().len())
                    .any(|idx| symtab.symbol_idx(idx).1.name() == LOCAL_VAR_NAME),
                "relocated object symbol table should include the global object symbol"
            );
            let (symbol, _) = (0..symtab.symbols().len())
                .map(|idx| symtab.symbol_idx(idx))
                .find(|(_, info)| info.name() == LOCAL_VAR_NAME)
                .expect("local var symbol should exist");
            let addr = event.core().base() + VmOffset::new(symbol.st_value());
            let mut bytes = [0u8; 4];
            event.memory().read_bytes(addr, &mut bytes)?;
            assert_eq!(bytes, [0u8; 4]);
            event.clear_exports();
            Ok(())
        }
    }

    let object_file = ObjectWriter::new(Arch::current())
        .write(
            &[SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40])],
            &[],
        )
        .expect("failed to generate object");

    let loaded_object = elf_loader::Loader::new()
        .load_object(elf_loader::input::ElfBinary::new(
            "test_static_clear_exports.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .observer(ClearExports)
        .relocate()
        .expect("relocation failed");

    assert!(
        unsafe { loaded_object.get::<i32>(LOCAL_VAR_NAME) }.is_none(),
        "object export event should be able to replace the default exports"
    );
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_layout_group_applies_final_protection_after_init() {
    use elf_loader::{
        Result,
        input::ElfBinary,
        memory::{MappedRegion, RegionAccess, VmAddr},
        observer::{
            LoadObserver, SectionGroup, SectionGroups, SectionLayoutEvent, SectionLifetime,
        },
        os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags},
    };
    use gen_elf::{Arch, ObjectWriter, SymbolDesc};
    use std::{
        alloc::{Layout, alloc_zeroed, dealloc},
        ptr::NonNull,
        sync::{Arc, Mutex},
    };
    use support::host_symbols::LOCAL_VAR_NAME;

    #[derive(Clone, Copy)]
    struct ProtectionCall {
        addr: usize,
        prot: i32,
    }

    #[derive(Clone)]
    struct RecordingMmap {
        calls: Arc<Mutex<Vec<ProtectionCall>>>,
    }

    struct RecordingRegion {
        ptr: usize,
        len: usize,
        layout: Layout,
        calls: Arc<Mutex<Vec<ProtectionCall>>>,
    }

    impl RecordingRegion {
        fn new(len: usize, calls: Arc<Mutex<Vec<ProtectionCall>>>) -> Self {
            let layout = Layout::from_size_align(len.max(1), 4096).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            assert!(!ptr.is_null(), "test allocation failed");
            Self {
                ptr: ptr as usize,
                len,
                layout,
                calls,
            }
        }
    }

    impl Drop for RecordingRegion {
        fn drop(&mut self) {
            unsafe {
                dealloc(self.ptr as *mut u8, self.layout);
            }
        }
    }

    unsafe impl Send for RecordingRegion {}
    unsafe impl Sync for RecordingRegion {}

    impl RegionAccess for RecordingRegion {
        fn addr(&self) -> VmAddr {
            VmAddr::new(self.ptr)
        }

        fn len(&self) -> usize {
            self.len
        }

        unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.ptr as *const u8).add(offset),
                    dst.as_mut_ptr(),
                    dst.len(),
                );
            }
            Ok(())
        }

        unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    (self.ptr as *mut u8).add(offset),
                    src.len(),
                );
            }
            Ok(())
        }

        unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
            unsafe {
                core::ptr::write_bytes((self.ptr as *mut u8).add(offset), 0, len);
            }
            Ok(())
        }

        unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
            Some(unsafe { core::slice::from_raw_parts((self.ptr as *const u8).add(offset), len) })
        }

        unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>> {
            NonNull::new(unsafe { (self.ptr as *mut u8).add(offset) })
        }

        unsafe fn madvise(
            &self,
            _offset: usize,
            _len: usize,
            _behavior: MadviseAdvice,
        ) -> Result<()> {
            Ok(())
        }

        unsafe fn mprotect(&self, offset: usize, _len: usize, prot: ProtFlags) -> Result<()> {
            self.calls.lock().unwrap().push(ProtectionCall {
                addr: self.ptr + offset,
                prot: prot.bits(),
            });
            Ok(())
        }
    }

    impl Mmap for RecordingMmap {
        type Region = RecordingRegion;

        fn page_size(&self) -> PageSize {
            PageSize::Base
        }

        unsafe fn create_space(
            &self,
            _addr: Option<VmAddr>,
            len: usize,
            _prot: ProtFlags,
            _populate_later: bool,
        ) -> Result<MappedRegion<Self::Region>> {
            Ok(MappedRegion::new(RecordingRegion::new(
                len,
                Arc::clone(&self.calls),
            )))
        }

        unsafe fn alias_space(
            &self,
            _addr: VmAddr,
            len: usize,
        ) -> Result<MappedRegion<Self::Region>> {
            unsafe {
                self.create_space(
                    None,
                    len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    false,
                )
            }
        }

        unsafe fn map_file_at(
            &self,
            _addr: VmAddr,
            _len: usize,
            _prot: ProtFlags,
            _flags: MapFlags,
            _offset: usize,
            _fd: isize,
        ) -> Result<()> {
            Ok(())
        }

        unsafe fn map_zero_at(
            &self,
            _addr: VmAddr,
            _len: usize,
            _prot: ProtFlags,
            _flags: MapFlags,
        ) -> Result<()> {
            Ok(())
        }

        unsafe fn munmap(&self, _addr: VmAddr, _len: usize) -> Result<()> {
            Ok(())
        }

        unsafe fn madvise(
            &self,
            _addr: VmAddr,
            _len: usize,
            _behavior: MadviseAdvice,
        ) -> Result<()> {
            Ok(())
        }

        unsafe fn mprotect(&self, _addr: VmAddr, _len: usize, _prot: ProtFlags) -> Result<()> {
            Ok(())
        }
    }

    struct ReadOnlyAfterInit {
        ro_after_init: SectionGroup,
    }

    impl LoadObserver for ReadOnlyAfterInit {
        fn on_section_layout(&mut self, event: &mut SectionLayoutEvent<'_>) -> Result<()> {
            let data = event
                .sections()
                .find_section(".data")
                .expect("generated object should contain .data");
            event.place(data, self.ro_after_init);
            Ok(())
        }
    }

    let calls = Arc::new(Mutex::new(Vec::new()));
    let object_file = ObjectWriter::new(Arch::current())
        .write(
            &[SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 0x40])],
            &[],
        )
        .expect("failed to generate object");
    let mut groups = SectionGroups::default();
    let ro_after_init = groups.define(
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        ProtFlags::PROT_READ,
        20,
        SectionLifetime::Core,
    );

    let _loaded_object = elf_loader::Loader::new()
        .with_object_section_groups(groups)
        .with_mmap(RecordingMmap {
            calls: Arc::clone(&calls),
        })
        .with_observer(ReadOnlyAfterInit { ro_after_init })
        .load_object(ElfBinary::new(
            "test_static_final_protection.o",
            &object_file.data,
        ))
        .expect("failed to load object")
        .relocator()
        .relocate()
        .expect("relocation failed");

    let calls = calls.lock().unwrap();
    let init_prot = (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE).bits();
    let final_prot = ProtFlags::PROT_READ.bits();
    let mut saw_transition = false;
    for (idx, init_call) in calls.iter().enumerate() {
        if init_call.prot != init_prot {
            continue;
        }
        saw_transition = calls
            .iter()
            .skip(idx + 1)
            .any(|final_call| final_call.addr == init_call.addr && final_call.prot == final_prot);
        if saw_transition {
            break;
        }
    }
    assert!(
        saw_transition,
        "object layout should apply final protection after init"
    );
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
#[test]
fn object_finalizer_runs_on_drop() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        input::ElfBinary,
        memory::VmAddr,
        runtime::{CodeContext, CodeExecutor},
    };
    use object::{
        Architecture, BinaryFormat, Endianness, SectionFlags, SectionKind, SymbolFlags, SymbolKind,
        SymbolScope,
        elf::{SHF_ALLOC, SHF_WRITE, SHT_FINI_ARRAY},
        write::{Object, Symbol, SymbolSection},
    };
    use std::sync::{Arc, Mutex};

    struct RecordingExecutor {
        fini_calls: Arc<Mutex<Vec<usize>>>,
    }

    impl CodeExecutor<NativeArch> for RecordingExecutor {
        fn call_init(&self, _ctx: CodeContext<'_, NativeArch>, _init: VmAddr) -> Result<()> {
            Ok(())
        }

        fn call_fini(&self, _ctx: CodeContext<'_, NativeArch>, fini: VmAddr) -> Result<()> {
            self.fini_calls.lock().unwrap().push(fini.get());
            Ok(())
        }

        fn resolve_ifunc(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            resolver: VmAddr,
        ) -> Result<VmAddr> {
            Ok(resolver)
        }
    }

    fn object_with_fini_array(fini_addr: usize) -> Vec<u8> {
        let mut object = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let data = object.add_section(Vec::new(), b".data".to_vec(), SectionKind::Data);
        let value = object.append_section_data(data, &[0; 8], 8);
        object.add_symbol(Symbol {
            name: b"keep".to_vec(),
            value,
            size: 8,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(data),
            flags: SymbolFlags::None,
        });

        let fini = object.add_section(
            Vec::new(),
            b".fini_array".to_vec(),
            SectionKind::Elf(SHT_FINI_ARRAY),
        );
        object.section_mut(fini).flags = SectionFlags::Elf {
            sh_flags: u64::from(SHF_ALLOC | SHF_WRITE),
        };
        object.append_section_data(fini, &fini_addr.to_ne_bytes(), 8);
        object.write().expect("failed to generate fini object")
    }

    let fini_calls = Arc::new(Mutex::new(Vec::new()));
    let executor = RecordingExecutor {
        fini_calls: Arc::clone(&fini_calls),
    };
    let fini_addr = 0x1234_5678usize;
    let object = object_with_fini_array(fini_addr);

    let loaded_object = elf_loader::Loader::new()
        .load_object(ElfBinary::new("test_static_fini.o", &object))
        .expect("failed to load object")
        .relocator()
        .executor(executor)
        .relocate()
        .expect("relocation failed");

    assert!(
        fini_calls.lock().unwrap().is_empty(),
        "fini should not run before unload"
    );
    drop(loaded_object);
    assert_eq!(&*fini_calls.lock().unwrap(), &[fini_addr]);
}
