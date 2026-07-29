use elf_loader::{Module, Relocator};

#[test]
fn applies_final_protection() {
    use elf_loader::{
        Result,
        input::ElfBinary,
        memory::{MappedRegion, RegionAccess, VmAddr},
        observer::{
            LoadObserver, SectionGroup, SectionGroups, SectionLayoutEvent, SectionLifetime,
        },
        os::{MadviseAdvice, MapFlags, Mmap, PageSize, ProtFlags},
    };
    use std::{
        alloc::{Layout, alloc_zeroed, dealloc},
        ptr::NonNull,
        sync::{Arc, Mutex},
    };

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
                .find_section(".data.value")
                .expect("compiled object should contain .data.value");
            event.place(data, self.ro_after_init);
            Ok(())
        }
    }

    let calls = Arc::new(Mutex::new(Vec::new()));
    let object = &crate::fixture::fixtures().provider_object;
    let mut groups = SectionGroups::default();
    let ro_after_init = groups.define(
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        ProtFlags::PROT_READ,
        20,
        SectionLifetime::Core,
    );

    let _loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .with_mmap(RecordingMmap {
                    calls: Arc::clone(&calls),
                })
                .run()
                .with_object_section_groups(groups)
                .with_observer(ReadOnlyAfterInit { ro_after_init })
                .load_object(ElfBinary::new("a.o", object))
                .expect("failed to load object"),
        )
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

#[test]
fn finalizer_runs_on_drop() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        input::ElfBinary,
        memory::VmAddr,
        runtime::{CodeContext, CodeExecutor},
        tls::TlsIndex,
    };
    use object::{
        Architecture, BinaryFormat, Endianness, SectionFlags, SectionKind, SymbolFlags, SymbolKind,
        SymbolScope,
        elf::{SHF_ALLOC, SHF_WRITE, SHT_FINI_ARRAY},
        write::{Object, Symbol, SymbolSection},
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RecordingExecutor {
        fini_calls: Arc<Mutex<Vec<usize>>>,
    }

    impl CodeExecutor<NativeArch> for RecordingExecutor {
        fn call_lifecycle(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            function: VmAddr,
        ) -> Result<()> {
            self.fini_calls.lock().unwrap().push(function.get());
            Ok(())
        }

        fn resolve_ifunc(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            resolver: VmAddr,
        ) -> Result<VmAddr> {
            Ok(resolver)
        }

        fn resolve_tls(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            resolver: VmAddr,
            _index: TlsIndex,
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

    let loaded_object = Relocator::new()
        .run(
            elf_loader::Loader::new()
                .with_executor(executor)
                .load_object(ElfBinary::new("test_static_fini.o", &object))
                .expect("failed to load object"),
        )
        .relocate()
        .expect("relocation failed");

    assert!(
        fini_calls.lock().unwrap().is_empty(),
        "fini should not run before unload"
    );
    drop(loaded_object);
    assert_eq!(&*fini_calls.lock().unwrap(), &[fini_addr]);
}

#[test]
fn defers_initialization() {
    use elf_loader::{
        Result,
        arch::NativeArch,
        input::ElfBinary,
        memory::{RegionAccess, VmAddr},
        observer::{ObjectRelocatedEvent, RelocationObserver},
        runtime::{CodeContext, CodeExecutor},
        tls::{TlsIndex, TlsResolver},
    };
    use std::sync::{Arc, Mutex};

    struct InitObserver(VmAddr);

    impl RelocationObserver for InitObserver {
        fn on_object_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>>(
            &mut self,
            event: &mut ObjectRelocatedEvent<'_, D, NativeArch, R, Tls>,
        ) -> Result<()> {
            event.lifecycle_mut().init_mut().push(self.0);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingExecutor(Arc<Mutex<Vec<usize>>>);

    impl CodeExecutor<NativeArch> for RecordingExecutor {
        fn call_lifecycle(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            function: VmAddr,
        ) -> Result<()> {
            self.0.lock().unwrap().push(function.get());
            Ok(())
        }

        fn resolve_ifunc(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            resolver: VmAddr,
        ) -> Result<VmAddr> {
            Ok(resolver)
        }

        fn resolve_tls(
            &self,
            _ctx: CodeContext<'_, NativeArch>,
            resolver: VmAddr,
            _index: TlsIndex,
        ) -> Result<VmAddr> {
            Ok(resolver)
        }
    }

    let object = &crate::fixture::fixtures().provider_object;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let init_addr = VmAddr::new(0x1234_5678);
    let loaded = Relocator::new()
        .defer_init()
        .run(
            elf_loader::Loader::new()
                .with_executor(RecordingExecutor(Arc::clone(&calls)))
                .load_object(ElfBinary::new("a.o", object))
                .expect("failed to load object"),
        )
        .observer(InitObserver(init_addr))
        .relocate()
        .expect("failed to relocate object");

    assert!(!loaded.is_init());
    assert!(calls.lock().unwrap().is_empty());

    loaded.initialize().expect("initialization should succeed");
    loaded
        .initialize()
        .expect("repeated initialization should be a no-op");
    assert!(loaded.is_init());
    assert_eq!(&*calls.lock().unwrap(), &[init_addr.get()]);
}
