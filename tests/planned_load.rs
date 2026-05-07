mod support;

use elf_loader::{
    CustomError, Loader,
    elf::{ElfFileType, ElfProgramType},
    image::{LoadedCore, LoadedModule, ModuleCapability, ScannedElf},
    input::ElfBinary,
    linker::{Arena, ArenaSharing, MemoryClass},
    linker::{
        DataPass, KeyResolver, LinkContext, LinkPass, LinkPassPlan, Linker, LoadObserver,
        Materialization, RelocationInputs, RelocationRequest, ReorderPass, ResolvedKey,
        StagedDynamic, VisibleModules,
    },
    os::PageSize,
};
use gen_elf::{ElfWriterConfig, SymbolDesc};
use std::{boxed::Box, cell::RefCell, rc::Rc, vec::Vec};
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

struct RecordingObserver {
    events: Rc<RefCell<Vec<String>>>,
}

struct FailingObserver;

struct VisibleDependencyResolver {
    root_data: &'static [u8],
}

struct StaticVisibleModule {
    key: &'static str,
    module: LoadedCore<()>,
    direct_deps: Box<[&'static str]>,
}

impl KeyResolver<'static, &'static str, ()> for SingleBinaryResolver {
    fn load_root(
        &mut self,
        key: &&'static str,
    ) -> elf_loader::Result<ResolvedKey<'static, &'static str>> {
        assert_eq!(*key, self.key);
        Ok(ResolvedKey::load(
            self.key,
            ElfBinary::new(self.name, self.data),
        ))
    }

    fn resolve_dependency(
        &mut self,
        _req: &elf_loader::linker::DependencyRequest<'_, &'static str, ()>,
    ) -> elf_loader::Result<Option<ResolvedKey<'static, &'static str>>> {
        Ok(None)
    }
}

impl KeyResolver<'static, &'static str, ()> for ExistingRootResolver {
    fn load_root(
        &mut self,
        key: &&'static str,
    ) -> elf_loader::Result<ResolvedKey<'static, &'static str>> {
        assert_eq!(*key, self.requested);
        Ok(ResolvedKey::existing(self.existing))
    }

    fn resolve_dependency(
        &mut self,
        _req: &elf_loader::linker::DependencyRequest<'_, &'static str, ()>,
    ) -> elf_loader::Result<Option<ResolvedKey<'static, &'static str>>> {
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

impl KeyResolver<'static, &'static str, ()> for MultiBinaryResolver {
    fn load_root(
        &mut self,
        key: &&'static str,
    ) -> elf_loader::Result<ResolvedKey<'static, &'static str>> {
        assert_eq!(*key, self.root);
        let module = self.module(key).expect("missing root module");
        Ok(ResolvedKey::load(
            module.key,
            ElfBinary::new(module.name, module.data),
        ))
    }

    fn resolve_dependency(
        &mut self,
        req: &elf_loader::linker::DependencyRequest<'_, &'static str, ()>,
    ) -> elf_loader::Result<Option<ResolvedKey<'static, &'static str>>> {
        Ok(self
            .module(req.needed())
            .map(|module| ResolvedKey::load(module.key, ElfBinary::new(module.name, module.data))))
    }
}

impl LoadObserver<&'static str, ()> for RecordingObserver {
    fn on_staged_dynamic(
        &mut self,
        event: StagedDynamic<'_, &'static str, ()>,
    ) -> elf_loader::Result<()> {
        assert!(event.mapped_len() > 0);
        self.events.borrow_mut().push((*event.key()).to_string());
        Ok(())
    }
}

impl LoadObserver<&'static str, ()> for FailingObserver {
    fn on_staged_dynamic(
        &mut self,
        _event: StagedDynamic<'_, &'static str, ()>,
    ) -> elf_loader::Result<()> {
        Err(elf_loader::Error::Custom(CustomError::Message(
            "observer failed".into(),
        )))
    }
}

impl KeyResolver<'static, &'static str, ()> for VisibleDependencyResolver {
    fn load_root(
        &mut self,
        key: &&'static str,
    ) -> elf_loader::Result<ResolvedKey<'static, &'static str>> {
        assert_eq!(*key, "root");
        Ok(ResolvedKey::load(
            "root",
            ElfBinary::new("visible_root.so", self.root_data),
        ))
    }

    fn resolve_dependency(
        &mut self,
        req: &elf_loader::linker::DependencyRequest<'_, &'static str, ()>,
    ) -> elf_loader::Result<Option<ResolvedKey<'static, &'static str>>> {
        assert_eq!(req.needed(), "dep");
        assert!(req.is_visible(&"dep"));
        Ok(Some(ResolvedKey::existing("dep")))
    }
}

impl VisibleModules<&'static str, ()> for StaticVisibleModule {
    fn contains_key(&self, key: &&'static str) -> bool {
        *key == self.key
    }

    fn direct_deps(&self, key: &&'static str) -> Option<Box<[&'static str]>> {
        (*key == self.key).then(|| self.direct_deps.clone())
    }

    fn loaded(&self, key: &&'static str) -> Option<LoadedModule<()>> {
        (*key == self.key).then(|| LoadedModule::from(self.module.clone()))
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

fn empty_relocation_plan(
    _req: &RelocationRequest<'_, &'static str, ()>,
) -> Result<RelocationInputs<()>, elf_loader::Error> {
    Ok(RelocationInputs::new(Vec::<LoadedModule<()>>::new()))
}

#[test]
fn load_uses_configured_visible_modules_without_committing_them_locally() {
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
        .planner(empty_relocation_plan)
        .load(&mut context, "root")
        .expect("load should resolve dependency through visible overlay");

    assert_eq!(root.short_name(), "visible_root.so");
    assert!(context.contains_key(&"root"));
    assert!(!context.contains_key(&"dep"));
    assert_eq!(context.direct_deps(&"root"), Some(&["dep"][..]));
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
        .planner(empty_relocation_plan)
        .load(&mut context, "root")
        .expect("legacy linker load should accept dynamic ET_EXEC roots");

    assert!(context.contains_key(&"root"));
    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[1, 2, 3, 4]);
    }
}

#[test]
fn load_dynamic_accepts_dynamic_exec_without_relaxing_load_dylib() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[9, 8, 7, 6])]);
    let bytes: &'static [u8] = Box::leak(mark_dynamic_as_exec(output.data).into_boxed_slice());

    let mut strict_loader = Loader::new();
    assert!(
        strict_loader
            .load_dylib(ElfBinary::new("dynamic_exec", bytes))
            .is_err(),
        "load_dylib should remain strict about ET_DYN"
    );

    let mut dynamic_loader = Loader::new();
    let loaded = dynamic_loader
        .load_dynamic(ElfBinary::new("dynamic_exec", bytes))
        .expect("load_dynamic should accept dynamic ET_EXEC")
        .relocator()
        .relocate()
        .expect("failed to relocate dynamic ET_EXEC");

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[9, 8, 7, 6]);
    }
}

#[test]
fn load_scanned_dynamic_accepts_dynamic_exec() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[4, 3, 2, 1])]);
    let bytes: &'static [u8] = Box::leak(mark_dynamic_as_exec(output.data).into_boxed_slice());

    let mut loader = Loader::new();
    let ScannedElf::Dynamic(scanned) = loader
        .scan(ElfBinary::new("scanned_dynamic_exec", bytes))
        .expect("scan should accept dynamic ET_EXEC")
    else {
        panic!("dynamic ET_EXEC should scan as dynamic");
    };
    let loaded = loader
        .load_scanned_dynamic(scanned)
        .expect("load_scanned_dynamic should accept scanned dynamic ET_EXEC")
        .relocator()
        .relocate()
        .expect("failed to relocate scanned dynamic ET_EXEC");

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
        assert_eq!(std::slice::from_raw_parts(ptr, 4), &[4, 3, 2, 1]);
    }
}

#[test]
fn scan_classifies_dynamic_and_static_exec() {
    let dynamic_output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1])]);
    let dynamic_bytes: &'static [u8] = Box::leak(dynamic_output.data.into_boxed_slice());
    let mut loader = Loader::new();

    let scanned_dynamic = loader
        .scan(ElfBinary::new("scanned.so", dynamic_bytes))
        .expect("scan should accept dynamic image");
    let ScannedElf::Dynamic(dynamic) = scanned_dynamic else {
        panic!("PT_DYNAMIC image should scan as dynamic");
    };
    assert_eq!(dynamic.name(), "scanned.so");
    assert!(dynamic.dynamic().bind_now());

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
    S: elf_loader::linker::PassScopeMode,
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
            let root = plan.root();
            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            plan.data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[9, 8, 7, 6]);
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute scan-first load");

    assert!(loaded.is_contiguous_mapping());
    assert!(loaded.mapped_len() > 0);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute merged scan-and-load path");

    assert!(loaded.is_contiguous_mapping());
    assert!(loaded.mapped_len() > 0);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("scan-first linker load should accept dynamic ET_EXEC roots");

    assert!(context.contains_key(&"root"));
    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "canonical")
        .expect("failed to load canonical scan root");

    let alias_resolver = ExistingRootResolver {
        requested: "alias",
        existing: "canonical",
    };
    let alias_loaded = Linker::new()
        .resolver(alias_resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "alias")
        .expect("failed to reuse existing scan root");

    assert_eq!(alias_loaded.base(), loaded.base());
    assert_eq!(alias_loaded.mapped_len(), loaded.mapped_len());
    assert!(context.contains_key(&"canonical"));
    assert!(!context.contains_key(&"alias"));
}

#[test]
fn load_observer_fires_for_runtime_root_and_dependency_before_relocation() {
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

    let observed = Rc::new(RefCell::new(Vec::new()));
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
    let observer = RecordingObserver {
        events: Rc::clone(&observed),
    };
    let planner = {
        let observed = Rc::clone(&observed);
        let planned = Rc::clone(&planned);
        move |req: &RelocationRequest<'_, &'static str, ()>| {
            planned.borrow_mut().push((*req.key()).to_string());
            assert_eq!(
                *observed.borrow(),
                vec!["root".to_string(), "dep".to_string()],
                "all staged modules should be observed before relocation planning"
            );
            Ok(RelocationInputs::new(Vec::<LoadedModule<()>>::new()))
        }
    };

    let mut context = LinkContext::<&'static str, ()>::new();
    Linker::new()
        .resolver(resolver)
        .observer(observer)
        .planner(planner)
        .load(&mut context, "root")
        .expect("failed to load root with dependency");

    assert_eq!(
        *observed.borrow(),
        vec!["root".to_string(), "dep".to_string()]
    );
    assert_eq!(
        *planned.borrow(),
        vec!["dep".to_string(), "root".to_string()],
        "relocation should still run in dependency-first order"
    );
    assert!(context.contains_key(&"root"));
    assert!(context.contains_key(&"dep"));
}

#[test]
fn load_scan_first_observer_fires_after_scan_materialization() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.into_boxed_slice());

    let observed = Rc::new(RefCell::new(Vec::new()));
    let saw_scan_phase = Rc::new(RefCell::new(false));
    let configure = {
        let observed = Rc::clone(&observed);
        let saw_scan_phase = Rc::clone(&saw_scan_phase);
        move |_plan: &mut LinkPassPlan<'_, &'static str>| -> elf_loader::Result<()> {
            assert!(
                observed.borrow().is_empty(),
                "scan planning must not notify the staged RawDynamic observer"
            );
            *saw_scan_phase.borrow_mut() = true;
            Ok(())
        }
    };

    let mut context = LinkContext::<&'static str, ()>::new();
    Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(SingleBinaryResolver {
            key: "root",
            name: "scan_observer_root.so",
            data: bytes,
        })
        .observer(RecordingObserver {
            events: Rc::clone(&observed),
        })
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute scan-first observer test");

    assert!(*saw_scan_phase.borrow());
    assert_eq!(*observed.borrow(), vec!["root".to_string()]);
    assert!(context.contains_key(&"root"));
}

#[test]
fn load_observer_error_aborts_without_committing_context() {
    let output = write_test_dylib(&[], &[SymbolDesc::global_object("value", &[1, 2, 3, 4])]);
    let bytes: &'static [u8] = Box::leak(output.data.into_boxed_slice());

    let mut context = LinkContext::<&'static str, ()>::new();
    let err = Linker::new()
        .resolver(SingleBinaryResolver {
            key: "root",
            name: "observer_error_root.so",
            data: bytes,
        })
        .observer(FailingObserver)
        .planner(empty_relocation_plan)
        .load(&mut context, "root")
        .expect_err("observer error should abort load");

    assert!(err.to_string().contains("observer failed"));
    assert!(context.is_empty());
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
            let root = plan.root();
            assert!(
                plan.capability(root) == Some(ModuleCapability::SectionReorderable),
                "generated test dylib should expose retained relocation repair inputs",
            );

            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            {
                plan.data_mut(layout_section)?
                    .expect("missing materialized .data bytes")
                    .as_bytes_mut()
                    .copy_from_slice(&[9, 8, 7, 6]);
                let arena = plan.create_arena(Arena::new(
                    PageSize::Base,
                    MemoryClass::WritableData,
                    ArenaSharing::Private,
                ));
                assert!(
                    plan.assign(layout_section, arena, 0),
                    "failed to assign .data into arena",
                );
            }
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load");

    assert!(
        !loaded.is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
    let configure =
        |plan: &mut LinkPassPlan<'_, &'static str, ReorderPass>| -> elf_loader::Result<()> {
            let root = plan.root();
            assert!(
                plan.capability(root) == Some(ModuleCapability::SectionReorderable),
                "generated test dylib should expose retained relocation repair inputs",
            );

            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            plan.data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[4, 3, 2, 1]);

            let arena = plan.create_arena(Arena::new(
                PageSize::Base,
                MemoryClass::WritableData,
                ArenaSharing::Private,
            ));
            assert!(
                plan.assign_next(layout_section, arena),
                "failed to assign .data into arena at the next aligned offset",
            );
            observed_offset = plan
                .placement(layout_section)
                .map(|placement| placement.offset());
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to execute arena-backed scan-first load with assign_next");

    assert_eq!(observed_offset, Some(0));
    assert!(
        !loaded.is_contiguous_mapping(),
        "arena-backed load should expose a sparse mapped span",
    );
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
        let root = plan.root();
        observed_capability = plan.capability(root);
        Ok(())
    };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to load section-reorderable dylib through the default section-region path");

    assert_eq!(
        observed_capability,
        Some(ModuleCapability::SectionReorderable),
    );
    assert!(
        !loaded.is_contiguous_mapping(),
        "section-region default should materialize alloc sections into mapped arenas",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
        let root = plan.root();
        observed_capability = plan.capability(root);
        saw_missing_section_headers = plan
            .get(root)
            .and_then(|module| module.module().section_headers())
            .is_none();
        plan.set_materialization(root, Materialization::WholeDsoRegion);
        Ok(())
    };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("failed to load opaque dylib through scan-first path");

    assert_eq!(observed_capability, Some(ModuleCapability::Opaque));
    assert!(
        saw_missing_section_headers,
        "opaque modules should not expose a usable section table",
    );

    assert!(loaded.mapped_len() > 0);
    assert!(context.contains_key(&"root"));

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
        let root = plan.root();
        observed_capability = plan.capability(root);
        Ok(())
    };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
        .load_scan_first(&mut context, "root")
        .expect("scan-first load should downgrade unusable section tables");

    assert!(loaded.mapped_len() > 0);
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
            let root = plan.root();
            observed_capability = plan.capability(root);
            observed_materialization = plan.materialization(root);

            let data_section = plan
                .get(root)
                .expect("missing scanned root module")
                .module()
                .alloc_sections()
                .find(|section| section.name() == ".data")
                .expect("generated test dylib should contain a .data section")
                .id();
            let layout_section = plan
                .section(root, data_section)
                .expect("missing planned .data section");
            plan.data_mut(layout_section)?
                .expect("missing materialized .data bytes")
                .as_bytes_mut()
                .copy_from_slice(&[9, 8, 7, 6]);
            plan.set_materialization(root, Materialization::WholeDsoRegion);
            observed_materialization = plan.materialization(root);
            Ok(())
        };

    let loaded = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
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

    assert!(
        loaded.mapped_len() > 0,
        "whole-DSO materialization should expose at least one mapped area",
    );

    unsafe {
        let ptr = loaded
            .get::<u8>("value")
            .expect("missing exported object symbol")
            .into_raw() as *const u8;
        assert!(loaded.contains_addr(ptr as usize));
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
            let root = plan.root();
            observed_capability = plan.capability(root);

            assert_eq!(
                plan.set_materialization(root, Materialization::SectionRegions),
                None,
            );
            observed_materialization = plan.materialization(root);
            Ok(())
        };

    let err = Linker::new()
        .map_pipeline(|mut pipeline| {
            pipeline.push(TestPass(configure));
            pipeline
        })
        .resolver(resolver)
        .planner(empty_relocation_plan)
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
