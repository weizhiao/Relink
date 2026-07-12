mod support;

use elf_loader::{
    LinkContext, Linker, Loader, Relocator,
    arch::NativeArch,
    elf::{ElfFileType, ElfProgramType},
    image::{LoadedCore, ModuleCapability, ScannedElf, SyntheticModule},
    input::ElfBinary,
    linker::{
        KeyResolver, ResolvedKey, RootRequest, VisibleModule, VisibleModules,
        scan::{
            ArenaDescriptor, ArenaSharing, DataPass, LinkPass, LinkPassPlan, Materialization,
            MemoryClass, PassScopeMode, ReorderPass,
        },
    },
    memory::{RegionAccess, VmAddr},
    observer::{
        DynamicRelocatedEvent, LinkerObserver, LinkerRelocationEvent, LoadObserver,
        RelocationObserver,
    },
    os::PageSize,
    tls::TlsResolver,
};
use gen_elf::{ElfWriterConfig, SymbolDesc};
use std::{
    boxed::Box,
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
    vec::Vec,
};
use support::test_dylib::{load_relocated_dylib, write_test_dylib, write_test_dylib_with_config};

struct SingleBinaryResolver {
    key: &'static str,
    name: &'static str,
    data: &'static [u8],
}

struct ExistingRootResolver {
    requested: &'static str,
    existing: &'static str,
}

#[derive(Clone, Copy)]
struct BinaryModule {
    key: &'static str,
    name: &'static str,
    data: &'static [u8],
}

struct MultiBinaryResolver {
    root: &'static str,
    modules: Vec<BinaryModule>,
}

struct VisibleDependencyResolver {
    root_data: &'static [u8],
}

struct SyntheticDependencyResolver {
    root_data: &'static [u8],
}

struct StaticVisibleModule {
    key: &'static str,
    module: LoadedCore<()>,
    direct_deps: Box<[&'static str]>,
}

struct InitRecorder {
    calls: Arc<Mutex<Vec<String>>>,
    reverse: bool,
    fail: bool,
}

impl InitRecorder {
    fn new(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            calls,
            reverse: false,
            fail: false,
        }
    }

    fn reversed(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            calls,
            reverse: true,
            fail: false,
        }
    }

    fn failing(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            calls,
            reverse: false,
            fail: true,
        }
    }
}

impl LoadObserver for InitRecorder {}
impl LinkerObserver<&'static str, ()> for InitRecorder {
    fn on_init(
        &mut self,
        event: &mut elf_loader::observer::LinkerInitEvent<'_, &'static str, ()>,
    ) -> elf_loader::Result<()> {
        if self.reverse {
            event.modules_mut().reverse();
        }
        Ok(())
    }
}

impl RelocationObserver for InitRecorder {
    fn on_dynamic_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let calls = Arc::clone(&self.calls);
        let fail = self.fail;
        event.lifecycle_mut().set_init_hook(move |event| {
            calls.lock().unwrap().push(event.name().to_string());
            event.lifecycle_mut().clear();
            if fail {
                return Err(elf_loader::error::CustomError::message("initializer failed").into());
            }
            Ok(())
        });
        Ok(())
    }
}

impl KeyResolver<&'static str> for SingleBinaryResolver {
    fn load_root<'cfg>(
        &self,
        req: &RootRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        let key = req.key();
        assert_eq!(*key, self.key);
        Ok(ResolvedKey::load(
            self.key,
            ElfBinary::new(self.name, self.data),
        ))
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &elf_loader::linker::DependencyRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        Err(req.unresolved())
    }
}

impl KeyResolver<&'static str> for ExistingRootResolver {
    fn load_root<'cfg>(
        &self,
        req: &RootRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        let key = req.key();
        assert_eq!(*key, self.requested);
        assert!(req.contains_key(&self.existing));
        Ok(ResolvedKey::existing(self.existing))
    }

    fn resolve_dependency<'cfg>(
        &self,
        _req: &elf_loader::linker::DependencyRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        panic!("existing scan root should not resolve dependencies")
    }
}

impl MultiBinaryResolver {
    fn module(&self, key: &str) -> Option<BinaryModule> {
        self.modules
            .iter()
            .find(|module| module.key == key)
            .copied()
    }
}

impl KeyResolver<&'static str> for MultiBinaryResolver {
    fn load_root<'cfg>(
        &self,
        req: &RootRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        let key = req.key();
        assert_eq!(*key, self.root);
        let module = self.module(key).expect("missing root module");
        Ok(ResolvedKey::load(
            module.key,
            ElfBinary::new(module.name, module.data),
        ))
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &elf_loader::linker::DependencyRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        self.module(req.needed())
            .map(|module| ResolvedKey::load(module.key, ElfBinary::new(module.name, module.data)))
            .ok_or_else(|| req.unresolved())
    }
}

impl KeyResolver<&'static str> for VisibleDependencyResolver {
    fn load_root<'cfg>(
        &self,
        req: &RootRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        let key = req.key();
        assert_eq!(*key, "root");
        Ok(ResolvedKey::load(
            "root",
            ElfBinary::new("visible_root.so", self.root_data),
        ))
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &elf_loader::linker::DependencyRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        assert_eq!(req.needed(), "dep");
        assert!(req.contains_key(&"dep"));
        Ok(ResolvedKey::existing("dep"))
    }
}

impl KeyResolver<&'static str> for SyntheticDependencyResolver {
    fn load_root<'cfg>(
        &self,
        req: &RootRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        let key = req.key();
        assert_eq!(*key, "root");
        Ok(ResolvedKey::load(
            "root",
            ElfBinary::new("scan_synthetic_root.so", self.root_data),
        ))
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &elf_loader::linker::DependencyRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg, &'static str>>
    where
        &'static str: 'cfg,
    {
        assert_eq!(req.needed(), "dep");
        Ok(ResolvedKey::module(
            "dep",
            SyntheticModule::empty("dep"),
            Vec::new(),
        ))
    }
}

impl VisibleModules<&'static str> for StaticVisibleModule {
    fn contains(&self, key: &&'static str) -> bool {
        *key == self.key
    }

    fn module(&self, key: &&'static str) -> Option<VisibleModule<&'static str>> {
        (*key == self.key)
            .then(|| VisibleModule::new(self.module.clone(), self.direct_deps.clone()))
    }
}

#[cfg(target_pointer_width = "64")]
const E_PHOFF_OFFSET: usize = 0x20;
#[cfg(target_pointer_width = "64")]
const E_SHOFF_OFFSET: usize = 0x28;
const E_TYPE_OFFSET: usize = 0x10;
#[cfg(target_pointer_width = "64")]
const E_PHENTSIZE_OFFSET: usize = 0x36;
#[cfg(target_pointer_width = "64")]
const E_PHNUM_OFFSET: usize = 0x38;
#[cfg(target_pointer_width = "64")]
const E_SHNUM_OFFSET: usize = 0x3c;
#[cfg(target_pointer_width = "64")]
const E_SHSTRNDX_OFFSET: usize = 0x3e;

#[cfg(not(target_pointer_width = "64"))]
const E_PHOFF_OFFSET: usize = 0x1c;
#[cfg(not(target_pointer_width = "64"))]
const E_SHOFF_OFFSET: usize = 0x20;
#[cfg(not(target_pointer_width = "64"))]
const E_PHENTSIZE_OFFSET: usize = 0x2a;
#[cfg(not(target_pointer_width = "64"))]
const E_PHNUM_OFFSET: usize = 0x2c;
#[cfg(not(target_pointer_width = "64"))]
const E_SHNUM_OFFSET: usize = 0x30;
#[cfg(not(target_pointer_width = "64"))]
const E_SHSTRNDX_OFFSET: usize = 0x32;

fn set_ehdr_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn read_ehdr_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

#[cfg(target_pointer_width = "64")]
fn set_ehdr_usize(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

#[cfg(target_pointer_width = "64")]
fn read_ehdr_usize(bytes: &[u8], offset: usize) -> usize {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize
}

#[cfg(not(target_pointer_width = "64"))]
fn set_ehdr_usize(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

#[cfg(not(target_pointer_width = "64"))]
fn read_ehdr_usize(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn strip_section_headers(mut bytes: Vec<u8>) -> Vec<u8> {
    set_ehdr_usize(&mut bytes, E_SHOFF_OFFSET, 0);
    set_ehdr_u16(&mut bytes, E_SHNUM_OFFSET, 0);
    set_ehdr_u16(&mut bytes, E_SHSTRNDX_OFFSET, 0);
    bytes
}

fn break_section_name_table(mut bytes: Vec<u8>) -> Vec<u8> {
    set_ehdr_u16(&mut bytes, E_SHSTRNDX_OFFSET, u16::MAX);
    bytes
}

fn mark_dynamic_as_exec(mut bytes: Vec<u8>) -> Vec<u8> {
    set_ehdr_u16(&mut bytes, E_TYPE_OFFSET, ElfFileType::EXEC.raw());
    bytes
}

fn mark_as_static_exec(mut bytes: Vec<u8>) -> Vec<u8> {
    set_ehdr_u16(&mut bytes, E_TYPE_OFFSET, ElfFileType::EXEC.raw());
    let phoff = read_ehdr_usize(&bytes, E_PHOFF_OFFSET);
    let phentsize = read_ehdr_u16(&bytes, E_PHENTSIZE_OFFSET) as usize;
    let phnum = read_ehdr_u16(&bytes, E_PHNUM_OFFSET) as usize;

    for index in 0..phnum {
        let p_type_offset = phoff + index * phentsize;
        let p_type =
            u32::from_le_bytes(bytes[p_type_offset..p_type_offset + 4].try_into().unwrap());
        if p_type == ElfProgramType::DYNAMIC.raw() {
            bytes[p_type_offset..p_type_offset + 4]
                .copy_from_slice(&ElfProgramType::NULL.raw().to_le_bytes());
            return bytes;
        }
    }

    panic!("generated test image should contain PT_DYNAMIC");
}

#[test]
fn load_commits_configured_visible_modules() {
    let dep_output = write_test_dylib(&[], &[]);
    let mut loader = Loader::new();
    let dep = load_relocated_dylib(&mut loader, "visible_dep.so", &dep_output);
    let visible = StaticVisibleModule {
        key: "dep",
        module: dep.clone(),
        direct_deps: Box::new([]),
    };

    let root_output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_needed_lib("dep"),
        &[],
        &[],
    );
    let root_data: &'static [u8] = Box::leak(root_output.data.into_boxed_slice());
    let resolver = VisibleDependencyResolver { root_data };
    let mut context = LinkContext::<&'static str, ()>::new();

    let root = Linker::new()
        .visible_modules(visible)
        .resolver(resolver)
        .load(&mut context, "root")
        .expect("load should resolve dependency through visible overlay");

    assert_eq!(root.path().file_name(), "visible_root.so");
    assert!(context.contains_key(&"root"));
    let root_id = context
        .key_id(&"root")
        .and_then(|id| context.module_id(id).unwrap())
        .unwrap();
    let dep_id = context.key_id(&"dep").unwrap();
    let dep_module_id = context
        .module_id(dep_id)
        .unwrap()
        .expect("visible dependency should be committed into the context");
    assert_eq!(context.get(dep_module_id).unwrap().name(), "visible_dep.so");
    let direct_deps = context
        .direct_deps(root_id)
        .unwrap()
        .map(|(key, module)| (*context.key(key).unwrap(), module))
        .collect::<Vec<_>>();
    assert_eq!(direct_deps, vec![("dep", dep_module_id)]);
}

#[test]
fn load_scan_first_supports_synthetic_dependencies() {
    let root_output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_needed_lib("dep"),
        &[],
        &[SymbolDesc::global_object("root_value", &[2])],
    );
    let root_data: &'static [u8] = Box::leak(root_output.data.into_boxed_slice());
    let resolver = SyntheticDependencyResolver { root_data };
    let mut context = LinkContext::<&'static str, ()>::new();

    let root = Linker::new()
        .resolver(resolver)
        .load_scan_first(&mut context, "root")
        .expect("scan-first load should accept a synthetic dependency");

    assert_eq!(root.path().file_name(), "scan_synthetic_root.so");
    assert!(context.contains_key(&"root"));
    assert!(context.contains_key(&"dep"));

    let root_id = context
        .key_id(&"root")
        .and_then(|id| context.module_id(id).unwrap())
        .unwrap();
    let dep_id = context.key_id(&"dep").unwrap();
    let dep_module_id = context.module_id(dep_id).unwrap().unwrap();
    let dep_module = context
        .get(dep_module_id)
        .expect("synthetic dependency committed");
    assert_eq!(dep_module.name(), "dep");
    assert!(dep_module.downcast_ref::<SyntheticModule>().is_some());

    let direct_deps = context
        .direct_deps(root_id)
        .unwrap()
        .map(|(key, module)| (*context.key(key).unwrap(), module))
        .collect::<Vec<_>>();
    assert_eq!(direct_deps, vec![("dep", dep_module_id)]);
}

#[test]
fn load_accepts_dynamic_exec_root() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(mark_dynamic_as_exec(output.data).into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "dynamic_exec",
        data: bytes,
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .load(&mut context, "root")
        .expect("legacy linker load should accept dynamic ET_EXEC roots");

    assert!(context.contains_key(&"root"));
    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_dynamic_accepts_dynamic_exec_without_relaxing_load_dylib() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[9, 8, 7, 6])]);
    let bytes: &'static [u8] = Box::leak(mark_dynamic_as_exec(output.data).into_boxed_slice());

    let strict_loader = Loader::new();
    assert!(
        strict_loader
            .load_dylib(ElfBinary::new("dynamic_exec", bytes))
            .is_err(),
        "load_dylib should remain strict about ET_DYN"
    );

    let dynamic_loader = Loader::new();
    let loaded = Relocator::new()
        .run(
            dynamic_loader
                .load_dynamic(ElfBinary::new("dynamic_exec", bytes))
                .expect("load_dynamic should accept dynamic ET_EXEC"),
        )
        .relocate()
        .expect("failed to relocate dynamic ET_EXEC");

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_scanned_dynamic_accepts_dynamic_exec() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[4, 3, 2, 1])]);
    let bytes: &'static [u8] = Box::leak(mark_dynamic_as_exec(output.data).into_boxed_slice());

    let loader = Loader::new();
    let ScannedElf::Dynamic(scanned) = loader
        .scan(ElfBinary::new("scanned_dynamic_exec", bytes))
        .expect("scan should accept dynamic ET_EXEC")
    else {
        panic!("dynamic ET_EXEC should scan as dynamic");
    };
    let loaded = Relocator::new()
        .run(
            loader
                .load_scanned_dynamic(scanned)
                .expect("load_scanned_dynamic should accept scanned dynamic ET_EXEC"),
        )
        .relocate()
        .expect("failed to relocate scanned dynamic ET_EXEC");

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[4, 3, 2, 1]);
    }
}

#[test]
fn scan_classifies_dynamic_and_static_exec() {
    let dynamic_output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1])]);
    let dynamic_bytes: &'static [u8] = Box::leak(dynamic_output.data.into_boxed_slice());
    let loader = Loader::new();

    let scanned_dynamic = loader
        .scan(ElfBinary::new("scanned.so", dynamic_bytes))
        .expect("scan should accept dynamic image");
    let ScannedElf::Dynamic(dynamic) = scanned_dynamic else {
        panic!("PT_DYNAMIC image should scan as dynamic");
    };
    assert_eq!(dynamic.name(), "scanned.so");

    let static_output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[2])]);
    let static_bytes: &'static [u8] =
        Box::leak(mark_as_static_exec(static_output.data).into_boxed_slice());
    let scanned_static = loader
        .scan(ElfBinary::new("static_exec", static_bytes))
        .expect("scan should accept static executable metadata");
    let ScannedElf::StaticExec(exec) = scanned_static else {
        panic!("executable without PT_DYNAMIC should scan as static exec");
    };
    assert_eq!(exec.name(), "static_exec");
    assert!(
        exec.phdrs()
            .iter()
            .all(|phdr| phdr.program_type() != ElfProgramType::DYNAMIC)
    );
}

struct TestPass<F>(F);

impl<S, F> LinkPass<&'static str, S> for TestPass<F>
where
    S: PassScopeMode,
    F: for<'a> FnMut(&mut LinkPassPlan<'a, &'static str, S>) -> elf_loader::Result<()>,
{
    fn run(&mut self, plan: &mut LinkPassPlan<'_, &'static str, S>) -> elf_loader::Result<()> {
        (self.0)(plan)
    }
}

#[test]
fn load_with_scan_legacy_path_applies_section_overrides_and_exposes_mapped_span() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "planned_root.so",
        data: bytes,
    };
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, DataPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            layout_section
                .data_mut(plan)?
                .copy_from_slice(&[9, 8, 7, 6]);
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute scan-first load");

    assert!(loaded.segments().is_contiguous_mapping());
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_with_scan_legacy_path_loads_without_an_intermediate_plan() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "merged_root.so",
        data: bytes,
    };
    let loaded = Linker::new()
        .resolver(resolver)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute merged scan-and-load path");

    assert!(loaded.segments().is_contiguous_mapping());
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_scan_first_accepts_dynamic_exec_root() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[5, 6, 7, 8])]);
    let bytes: &'static [u8] = Box::leak(mark_dynamic_as_exec(output.data).into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "scanned_dynamic_exec",
        data: bytes,
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .load_scan_first(&mut context, "root")
        .expect("scan-first linker load should accept dynamic ET_EXEC roots");

    assert!(context.contains_key(&"root"));
    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[5, 6, 7, 8]);
    }
}

#[test]
fn load_with_scan_reuses_existing_root_alias_without_planning() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[5, 6, 7, 8])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();

    let load_resolver = SingleBinaryResolver {
        key: "canonical",
        name: "canonical.so",
        data: bytes,
    };
    let loaded = Linker::new()
        .resolver(load_resolver)
        .load_scan_first(&mut context, "canonical")
        .expect("failed to load canonical scan root");

    let alias_resolver = ExistingRootResolver {
        requested: "alias",
        existing: "canonical",
    };
    let alias_loaded = Linker::new()
        .resolver(alias_resolver)
        .load_scan_first(&mut context, "alias")
        .expect("failed to reuse existing scan root");

    assert_eq!(alias_loaded.base(), loaded.base());
    assert!(context.contains_key(&"canonical"));
    assert!(!context.contains_key(&"alias"));
}

#[test]
fn load_relocates_runtime_dependency_before_root() {
    let dep_output = write_test_dylib(&[], &[SymbolDesc::global_object("dep_value", &[1])]);
    let root_output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_needed_lib("dep"),
        &[],
        &[SymbolDesc::global_object("root_value", &[2])],
    );
    let dep_bytes: &'static [u8] = Box::leak(dep_output.data.into_boxed_slice());
    let root_bytes: &'static [u8] = Box::leak(root_output.data.into_boxed_slice());

    let planned = Rc::new(RefCell::new(Vec::new()));
    let resolver = MultiBinaryResolver {
        root: "root",
        modules: vec![
            BinaryModule {
                key: "root",
                name: "root.so",
                data: root_bytes,
            },
            BinaryModule {
                key: "dep",
                name: "dep.so",
                data: dep_bytes,
            },
        ],
    };
    struct PlanningObserver(Rc<RefCell<Vec<String>>>);

    impl LoadObserver for PlanningObserver {}
    impl RelocationObserver for PlanningObserver {}
    impl LinkerObserver<&'static str, ()> for PlanningObserver {
        fn on_relocation(
            &mut self,
            event: &mut LinkerRelocationEvent<()>,
        ) -> elf_loader::Result<()> {
            self.0.borrow_mut().push(event.raw().name().to_string());
            event.set_scope(elf_loader::image::ModuleScopeBuilder::new().into_scope());
            Ok(())
        }
    }

    let mut context = LinkContext::<&'static str, ()>::new();
    let linker = Linker::new().resolver(resolver);
    linker
        .run()
        .with_observer(PlanningObserver(Rc::clone(&planned)))
        .load(&mut context, "root")
        .expect("failed to load root with dependency");

    assert_eq!(
        *planned.borrow(),
        vec!["dep.so".to_string(), "root.so".to_string()],
        "relocation should still run in dependency-first order"
    );
    assert!(context.contains_key(&"root"));
    assert!(context.contains_key(&"dep"));
}

#[test]
fn phased_load_commits_before_dependency_ordered_initialization() {
    let dep_output = write_test_dylib(&[], &[]);
    let root_output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_needed_lib("dep"),
        &[],
        &[],
    );
    let dep_data: &'static [u8] = Box::leak(dep_output.data.into_boxed_slice());
    let root_data: &'static [u8] = Box::leak(root_output.data.into_boxed_slice());
    let resolver = MultiBinaryResolver {
        root: "root",
        modules: vec![
            BinaryModule {
                key: "root",
                name: "phased_root.so",
                data: root_data,
            },
            BinaryModule {
                key: "dep",
                name: "phased_dep.so",
                data: dep_data,
            },
        ],
    };
    let linker = Linker::new().resolver(resolver);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut run = linker
        .run()
        .with_observer(InitRecorder::new(Arc::clone(&calls)));
    let mut context = LinkContext::<&'static str, ()>::new();

    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should resolve the module group");
    assert!(!context.contains_key(&"root"));
    assert!(!context.contains_key(&"dep"));

    let relocated = run
        .relocate(prepared)
        .expect("relocation should succeed without a context borrow");
    assert!(!context.contains_key(&"root"));
    assert!(!context.contains_key(&"dep"));

    let committed = run
        .commit(&mut context, relocated)
        .expect("commit should publish the relocated group");
    assert!(context.contains_key(&"root"));
    assert!(context.contains_key(&"dep"));
    assert!(!committed.root().is_init());

    let result = run
        .initialize(committed)
        .expect("initialization should succeed");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["phased_dep.so".to_string(), "phased_root.so".to_string()]
    );
    assert!(result.root().is_init());

    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn linker_observer_can_reorder_initialization() {
    let dep_output = write_test_dylib(&[], &[]);
    let root_output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_needed_lib("dep"),
        &[],
        &[],
    );
    let dep_data: &'static [u8] = Box::leak(dep_output.data.into_boxed_slice());
    let root_data: &'static [u8] = Box::leak(root_output.data.into_boxed_slice());
    let resolver = MultiBinaryResolver {
        root: "root",
        modules: vec![
            BinaryModule {
                key: "root",
                name: "reordered_root.so",
                data: root_data,
            },
            BinaryModule {
                key: "dep",
                name: "reordered_dep.so",
                data: dep_data,
            },
        ],
    };
    let linker = Linker::new().resolver(resolver);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut context = LinkContext::<&'static str, ()>::new();

    linker
        .run()
        .with_observer(InitRecorder::reversed(Arc::clone(&calls)))
        .load(&mut context, "root")
        .expect("load with reordered initialization should succeed");

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[
            "reordered_root.so".to_string(),
            "reordered_dep.so".to_string(),
        ]
    );
}

#[test]
fn relocator_configuration_can_defer_dynamic_initialization() {
    let output = write_test_dylib(&[], &[]);
    let raw = Loader::new()
        .load_dylib(ElfBinary::new("deferred.so", &output.data))
        .expect("dynamic image should load");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let loaded = Relocator::new()
        .defer_init()
        .run(raw)
        .observer(InitRecorder::new(Arc::clone(&calls)))
        .relocate()
        .expect("dynamic image should relocate without initialization");

    assert!(!loaded.is_init());
    assert!(calls.lock().unwrap().is_empty());

    loaded
        .initialize()
        .expect("deferred initialization should succeed");
    assert!(loaded.is_init());
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["deferred.so".to_string()]
    );
}

#[test]
fn phased_load_rejects_a_different_commit_context() {
    let output = write_test_dylib(&[], &[]);
    let data: &'static [u8] = Box::leak(output.data.into_boxed_slice());
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "context_bound.so",
        data,
    });
    let mut run = linker.run();
    let mut prepared_context = LinkContext::<&'static str, ()>::new();
    let prepared = run
        .prepare_load(&mut prepared_context, "root")
        .expect("prepare should succeed");
    let relocated = run.relocate(prepared).expect("relocation should succeed");
    let mut other_context = LinkContext::<&'static str, ()>::new();

    let err = run
        .commit(&mut other_context, relocated)
        .expect_err("commit must reject another context");
    assert!(err.to_string().contains("different") || err.to_string().contains("prepared for"));
    assert!(!other_context.contains_key(&"root"));
}

#[test]
fn failed_initialization_can_be_rolled_back_after_reacquiring_context() {
    let output = write_test_dylib(&[], &[]);
    let data: &'static [u8] = Box::leak(output.data.into_boxed_slice());
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "failing_init.so",
        data,
    });
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut run = linker
        .run()
        .with_observer(InitRecorder::failing(Arc::clone(&calls)));
    let mut context = LinkContext::<&'static str, ()>::new();
    let prepared = run.prepare_load(&mut context, "root").unwrap();
    let relocated = run.relocate(prepared).unwrap();
    let committed = run.commit(&mut context, relocated).unwrap();

    let failed = run
        .initialize(committed)
        .expect_err("initializer should fail");
    assert!(context.contains_key(&"root"));
    assert!(failed.error().to_string().contains("initializer failed"));

    let error = run.rollback(&mut context, failed);
    assert!(error.to_string().contains("initializer failed"));
    assert!(!context.contains_key(&"root"));
    assert_eq!(calls.lock().unwrap().as_slice(), &["failing_init.so"]);
}

#[test]
fn load_with_scan_arena_backed_path_materializes_section_bytes_into_runtime_memory() {
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_emit_retained_relocations(true),
        &[],
        &[SymbolDesc::global_object("value", &[1, 2, 3, 4])],
    );
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_root.so",
        data: bytes,
    };
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            assert!(
                root.capability(plan) == ModuleCapability::SectionReorderable,
                "generated test dylib should expose retained relocation repair inputs",
            );

            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            {
                layout_section
                    .data_mut(plan)?
                    .copy_from_slice(&[9, 8, 7, 6]);
                let arena = plan.create_arena(ArenaDescriptor::new(
                    PageSize::Base,
                    MemoryClass::WritableData,
                    ArenaSharing::Private,
                ));
                assert!(
                    layout_section.assign(plan, arena, 0),
                    "failed to assign .data into arena",
                );
            }
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load");

    assert!(
        !loaded.segments().is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_with_scan_arena_backed_path_supports_assign_next() {
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_emit_retained_relocations(true),
        &[],
        &[SymbolDesc::global_object("value", &[1, 2, 3, 4])],
    );
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "arena_assign_next_root.so",
        data: bytes,
    };
    let mut observed_offset = None;
    let mut observed_size = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            assert!(
                root.capability(plan) == ModuleCapability::SectionReorderable,
                "generated test dylib should expose retained relocation repair inputs",
            );

            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            layout_section.resize(plan, 8)?;
            assert_eq!(layout_section.metadata(plan).size(), 8);
            layout_section
                .data_mut(plan)?
                .copy_from_slice(&[4, 3, 2, 1, 8, 7, 6, 5]);

            let arena = plan.create_arena(ArenaDescriptor::new(
                PageSize::Base,
                MemoryClass::WritableData,
                ArenaSharing::Private,
            ));
            assert!(
                layout_section.assign_next(plan, arena),
                "failed to assign .data into arena at the next aligned offset",
            );
            observed_offset = layout_section
                .placement(plan)
                .map(|placement| placement.offset());
            observed_size = layout_section
                .placement(plan)
                .map(|placement| placement.size());
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load with assign_next");

    assert_eq!(observed_offset, Some(0));
    assert_eq!(observed_size, Some(8));
    assert!(
        !loaded.segments().is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[4, 3, 2, 1]);
    }
}

#[test]
fn load_with_scan_defaults_section_reorderable_modules_to_section_regions() {
    let output = write_test_dylib_with_config(
        ElfWriterConfig::default()
            .with_bind_now(true)
            .with_emit_retained_relocations(true),
        &[],
        &[SymbolDesc::global_object("value", &[1, 2, 3, 4])],
    );
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "default_section_regions_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
        let root = plan.root().expect("root module should be visible");
        observed_capability = Some(root.capability(plan));
        Ok(())
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to load section-reorderable dylib through the default section-region path");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionReorderable),
    );
    assert!(
        !loaded.segments().is_contiguous_mapping(),
        "section-region default should materialize alloc sections into mapped arenas",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_with_scan_handles_missing_section_headers_as_opaque_module() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(strip_section_headers(output.data).into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "opaque_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut saw_missing_section_headers = false;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
        let root = plan.root().expect("root module should be visible");
        observed_capability = Some(root.capability(plan));
        saw_missing_section_headers = root.scanned(plan).section_headers().is_none();
        root.set_materialization(plan, Materialization::WholeDsoRegion);
        Ok(())
    };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to load opaque dylib through scan-first path");

    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
    assert!(
        saw_missing_section_headers,
        "opaque modules should not expose a usable section table",
    );

    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_with_scan_downgrades_unusable_section_table_to_opaque() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(break_section_name_table(output.data).into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "broken_shstr_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let configure = |plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
        let root = plan.root().expect("root module should be visible");
        observed_capability = Some(root.capability(plan));
        Ok(())
    };

    let _loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("scan-first load should downgrade unusable section tables");

    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
}

#[test]
fn load_with_scan_supports_whole_dso_regions_and_section_overrides_for_section_data_modules() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "whole_region_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, DataPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            observed_capability = Some(root.capability(plan));
            observed_materialization = root.materialization(plan);

            let data_section = root
                .scanned(plan)
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = root
                .section(plan, data_section)
                .expect("missing planned .data section");
            layout_section
                .data_mut(plan)?
                .copy_from_slice(&[9, 8, 7, 6]);
            root.set_materialization(plan, Materialization::WholeDsoRegion);
            observed_materialization = root.materialization(plan);
            Ok(())
        };

    let loaded = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect("failed to execute whole-DSO scan-first load");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionData),
        "no emit-relocs should classify as section-data only",
    );
    assert_eq!(
        observed_materialization,
        Some(Materialization::WholeDsoRegion),
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.segments().contains_addr(VmAddr::new(ptr as usize)));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_with_scan_rejects_section_regions_for_section_data_modules() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.clone().into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let resolver = SingleBinaryResolver {
        key: "root",
        name: "illegal_section_region_root.so",
        data: bytes,
    };
    let mut observed_capability = None;
    let mut observed_materialization = None;
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, DataPass>| -> elf_loader::Result<()> {
            let root = plan.root().expect("root module should be visible");
            observed_capability = Some(root.capability(plan));

            assert_eq!(
                root.set_materialization(plan, Materialization::SectionRegions),
                None,
            );
            observed_materialization = root.materialization(plan);
            Ok(())
        };

    let err = Linker::new()
        .resolver(resolver)
        .run()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .load_scan_first(&mut context, "root")
        .expect_err("section-data modules must reject section-region placement");
    assert_eq!(observed_capability, Some(ModuleCapability::SectionData));
    assert_eq!(
        observed_materialization,
        Some(Materialization::SectionRegions)
    );
    assert!(
        err.to_string().contains("cannot use section regions"),
        "unexpected error: {err}",
    );
}
