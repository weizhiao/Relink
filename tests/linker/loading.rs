use super::*;
use std::sync::OnceLock;

struct LoadingFixtures {
    provider: &'static [u8],
    dependent: &'static [u8],
    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    exec: &'static [u8],
    synthetic_root: ElfWriteOutput,
}

impl LoadingFixtures {
    fn new() -> Self {
        let eager = || ElfWriterConfig::default().with_bind_now(true);
        let real = crate::fixture::fixtures();
        Self {
            provider: &real.provider,
            dependent: &real.dependent,
            #[cfg(any(
                feature = "use-syscall",
                all(any(target_os = "linux", target_os = "android"), feature = "libc")
            ))]
            exec: &real.exec,
            synthetic_root: DylibWriter::with_config(
                Arch::current(),
                eager().with_needed_lib("dep"),
            )
            .write(&[], &[])
            .expect("failed to generate synthetic dependency root"),
        }
    }
}

fn fixtures() -> &'static LoadingFixtures {
    static FIXTURES: OnceLock<LoadingFixtures> = OnceLock::new();
    FIXTURES.get_or_init(LoadingFixtures::new)
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

fn dependency_resolver(root_name: &'static str, dep_name: &'static str) -> MultiBinaryResolver {
    let fixtures = fixtures();
    MultiBinaryResolver {
        root: "root",
        modules: vec![
            BinaryModule {
                key: "root",
                name: root_name,
                data: fixtures.dependent,
            },
            BinaryModule {
                key: DEP_KEY,
                name: dep_name,
                data: fixtures.provider,
            },
        ],
    }
}

#[test]
fn commits_visible_modules() {
    let fixtures = fixtures();
    let loader = Loader::new();
    let dep = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new("visible_dep.so", fixtures.provider))
                .expect("failed to load visible dependency"),
        )
        .relocate()
        .expect("failed to relocate visible dependency");
    let visible = StaticVisibleModule {
        key: DEP_KEY,
        module: dep.clone(),
        direct_deps: Box::new([]),
    };

    let resolver = VisibleDependencyResolver {
        root_data: fixtures.dependent,
    };
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    let linker = Linker::new().resolver(resolver);
    let root = linker
        .run()
        .with_observer(visible)
        .load(&mut context, "root")
        .expect("load should resolve dependency through visible overlay");

    assert_eq!(root.path().file_name(), "visible_root.so");
    assert!(context.contains_key(&"root"));
    let root_id = context
        .key_id(&"root")
        .and_then(|id| context.module_id(id).unwrap())
        .unwrap();
    let dep_id = context.key_id(&DEP_KEY).unwrap();
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
    assert_eq!(direct_deps, vec![(DEP_KEY, dep_module_id)]);
}

#[test]
fn scan_loads_synthetic_dependency() {
    let resolver = SyntheticDependencyResolver {
        root_data: &fixtures().synthetic_root.data,
    };
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

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
fn unresolved_dependency_does_not_commit() {
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    let error = Linker::new()
        .resolver(SingleBinaryResolver {
            key: "root",
            name: "unresolved_root.so",
            data: fixtures().dependent,
        })
        .load(&mut context, "root")
        .expect_err("missing dependency should fail before commit");

    assert!(matches!(
        error,
        Error::Linker(LinkerError::UnresolvedDependency(_))
    ));
    assert!(!context.contains_key(&"root"));
}

#[test]
#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
fn loads_dynamic_exec() {
    let fixtures = fixtures();

    for scan_first in [false, true] {
        let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);
        let linker = Linker::new().resolver(MultiBinaryResolver {
            root: "root",
            modules: vec![
                BinaryModule {
                    key: "root",
                    name: "dynamic_exec",
                    data: fixtures.exec,
                },
                BinaryModule {
                    key: DEP_KEY,
                    name: "libprovider.so",
                    data: fixtures.provider,
                },
            ],
        });
        let _loaded = if scan_first {
            linker.load_scan_first(&mut context, "root")
        } else {
            linker.load(&mut context, "root")
        }
        .expect("linker should accept dynamic ET_EXEC roots");

        assert!(context.contains_key(&"root"));
        assert!(context.contains_key(&DEP_KEY));
    }
}

#[test]
fn existing_alias_skips_planning() {
    let bytes = fixtures().provider;

    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

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
fn repeated_loads_acquire_the_root() {
    let linker = Linker::new().resolver(dependency_resolver("acquired_root.so", "acquired_dep.so"));
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    let first = linker
        .load(&mut context, "root")
        .expect("first load should succeed");
    let second = linker
        .load(&mut context, "root")
        .expect("existing root should be acquired");

    assert_eq!(first.root_id(), second.root_id());
    assert_eq!(first.modules().len(), 2);
    assert!(second.modules().is_empty());
    let dep = context
        .key_id(&DEP_KEY)
        .and_then(|key| context.module_id(key).unwrap())
        .expect("dependency should be committed");
    assert!(matches!(
        context.release(dep),
        Err(Error::Linker(LinkerError::Context { reason }))
            if matches!(*reason, LinkContextError::ModuleNotAcquired { id } if id == dep)
    ));
    assert!(context.release(first.root_id()).unwrap().is_empty());
    assert!(context.contains_key(&"root"));
    assert!(context.contains_key(&DEP_KEY));

    let unloaded = context.release(second.root_id()).unwrap();
    assert_eq!(
        unloaded
            .modules()
            .iter()
            .map(|entry| entry.module().name())
            .collect::<Vec<_>>(),
        ["acquired_root.so", "acquired_dep.so"]
    );
    assert!(context.is_empty());
}

#[test]
fn rollback_releases_existing_root() {
    let linker = Linker::new().resolver(dependency_resolver("rollback_root.so", "rollback_dep.so"));
    let mut run = linker.run();
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);
    let loaded = run
        .load(&mut context, "root")
        .expect("initial load should succeed");

    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("existing root should prepare");
    let relocated = run
        .relocate(prepared)
        .expect("existing root should relocate");
    relocated
        .publish(&mut context)
        .expect("existing root should publish")
        .rollback(&mut context)
        .expect("rollback should release the temporary acquisition");

    let unloaded = context
        .release(loaded.root_id())
        .expect("initial acquisition should remain");
    assert_eq!(unloaded.len(), 2);
    assert!(context.is_empty());
}

#[test]
fn relocates_dependencies_first() {
    let planned = Rc::new(RefCell::new(Vec::new()));
    let resolver = dependency_resolver("root.so", "dep.so");
    struct PlanningObserver(Rc<RefCell<Vec<String>>>);

    impl LoadObserver for PlanningObserver {}
    impl RelocationObserver for PlanningObserver {}
    impl LinkerObserver<&'static str, ()> for PlanningObserver {
        fn on_relocation(
            &mut self,
            event: &mut LinkerRelocationEvent<()>,
        ) -> elf_loader::Result<()> {
            self.0.borrow_mut().push(event.raw().name().to_string());
            Ok(())
        }
    }

    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);
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
    assert!(context.contains_key(&DEP_KEY));
}

#[test]
fn phased_load_initializes_dependencies_first() {
    let resolver = dependency_resolver("phased_root.so", "phased_dep.so");
    let linker = Linker::new().resolver(resolver);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut run = linker
        .run()
        .with_observer(InitRecorder::new(Arc::clone(&calls)));
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should resolve the module group");
    assert!(!context.contains_key(&"root"));
    assert!(!context.contains_key(&DEP_KEY));

    let relocated = run
        .relocate(prepared)
        .expect("relocation should succeed without a context borrow");
    assert!(!context.contains_key(&"root"));
    assert!(!context.contains_key(&DEP_KEY));

    let published = relocated
        .publish(&mut context)
        .expect("publish should expose the relocated group");
    assert!(context.contains_key(&"root"));
    assert!(context.contains_key(&DEP_KEY));
    assert!(!published.root().is_init());

    let result = published
        .initialize()
        .expect("initialization should succeed");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["phased_dep.so".to_string(), "phased_root.so".to_string()]
    );
    assert!(result.root().is_init());

    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn publish_rejects_other_context() {
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "context_bound.so",
        data: fixtures().provider,
    });
    let mut run = linker.run();
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);
    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should succeed");
    let relocated = run.relocate(prepared).expect("relocation should succeed");
    let mut other_context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    let err = relocated
        .publish(&mut other_context)
        .expect_err("publish must reject another context");
    assert!(matches!(
        err,
        Error::Linker(LinkerError::Context {
            reason,
        }) if matches!(*reason, LinkContextError::ContextMismatch { .. })
    ));
    assert!(!other_context.contains_key(&"root"));
}

#[test]
fn rollback_rejects_other_context() {
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "context_bound.so",
        data: fixtures().provider,
    });
    let mut run = linker.run();
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);
    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should succeed");
    let relocated = run.relocate(prepared).expect("relocation should succeed");
    let published = relocated
        .publish(&mut context)
        .expect("publish should succeed");
    let mut other_context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);

    let error = published
        .rollback(&mut other_context)
        .expect_err("rollback must reject another context");
    assert!(matches!(
        error,
        Error::Linker(LinkerError::Context {
            reason,
        }) if matches!(*reason, LinkContextError::ContextMismatch { .. })
    ));
    assert!(context.contains_key(&"root"));
    assert!(!other_context.contains_key(&"root"));
}

#[test]
fn failed_init_can_roll_back() {
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "failing_init.so",
        data: fixtures().provider,
    });
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut run = linker
        .run()
        .with_observer(InitRecorder::failing(Arc::clone(&calls)));
    let mut context = LinkContext::<&'static str, ()>::new(DomainId::PROCESS);
    let prepared = run.prepare_load(&mut context, "root").unwrap();
    let relocated = run.relocate(prepared).unwrap();
    let published = relocated.publish(&mut context).unwrap();

    let failed = published.initialize().expect_err("initializer should fail");
    assert!(context.contains_key(&"root"));
    assert!(failed.error().to_string().contains("initializer failed"));

    let error = failed.rollback(&mut context);
    assert!(error.to_string().contains("initializer failed"));
    assert!(!context.contains_key(&"root"));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["failing_init.so", "fini:failing_init.so"]
    );
}
