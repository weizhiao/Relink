use super::*;
use std::sync::OnceLock;

struct LoadingFixtures {
    provider: &'static [u8],
    dependent: &'static [u8],
    global: &'static [u8],
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
            global: &real.global,
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

impl KeyResolver for MultiBinaryResolver {
    type Root = &'static str;

    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg>> {
        let key = match req.input() {
            ResolveInput::Root { root } => {
                assert_eq!(*root, self.root);
                *root
            }
            ResolveInput::Dependency { needed } => *needed,
        };
        self.module(key)
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

fn load_provider(name: &'static str) -> LoadedCore<()> {
    load_provider_with_source(name, ModuleSourceId::fresh())
}

fn load_provider_with_source(name: &'static str, source: ModuleSourceId) -> LoadedCore<()> {
    Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new(name, fixtures().provider).with_source_id(source))
                .expect("failed to load provider"),
        )
        .relocate()
        .expect("failed to relocate provider")
}

struct CustomBinding;

impl LoadObserver for CustomBinding {}
impl LinkerObserver for CustomBinding {}
impl RelocationObserver for CustomBinding {
    fn on_relocation_pre<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
        H,
    >(
        &mut self,
        event: &mut RelocationEvent<'_, D, NativeArch, R, Tls, H>,
    ) -> elf_loader::Result<HandleResult> {
        let Some(symbol) = event.relocation_symbol() else {
            return Ok(HandleResult::Unhandled);
        };
        if symbol.name() != "provider_value" {
            return Ok(HandleResult::Unhandled);
        }

        let r_sym = event.rel().r_symbol();
        assert!(event.bind_symdef(r_sym).is_some());
        Ok(HandleResult::Handled)
    }
}

#[test]
fn commits_resolver_modules() {
    let fixtures = fixtures();
    let loader = Loader::new();
    let dep = Relocator::new()
        .defer_init()
        .run(
            loader
                .load_dylib(ElfBinary::new("visible_dep.so", fixtures.provider))
                .expect("failed to load visible dependency"),
        )
        .relocate()
        .expect("failed to relocate visible dependency");
    assert!(!dep.state().is_initialized());
    let resolver = ModuleDependencyResolver {
        root_data: fixtures.dependent,
        dep: dep.clone(),
    };
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);

    let linker = Linker::new().resolver(resolver);
    let root = linker
        .run()
        .load(&mut context, "root")
        .expect("load should accept a resolver-provided module");

    assert_eq!(
        context
            .module(root.root())
            .unwrap()
            .search()
            .unwrap()
            .path()
            .file_name(),
        "visible_root.so"
    );
    assert!(dep.state().is_initialized());
    assert!(context.contains_key("root"));
    let root_id = context
        .key_id("root")
        .and_then(|id| context.resolve_key(id).unwrap())
        .unwrap();
    let dep_id = context.key_id(DEP_KEY).unwrap();
    let dep_module_id = context
        .resolve_key(dep_id)
        .unwrap()
        .expect("resolver-provided dependency should be committed into the context");
    assert_eq!(
        context.module(dep_module_id).unwrap().name(),
        "visible_dep.so"
    );
    let direct_deps = context.direct_deps(root_id).unwrap().collect::<Vec<_>>();
    assert_eq!(direct_deps, vec![dep_module_id]);
}

#[test]
fn loads_module_root() {
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(SyntheticRootResolver);

    let first = linker.run().load(&mut context, "root").unwrap();
    assert!(
        context
            .module(first.root())
            .unwrap()
            .downcast_ref::<SyntheticModule>()
            .is_some()
    );
    let value = unsafe {
        context
            .module(first.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("synthetic_value")
            .unwrap()
    };
    assert_eq!(value(), 42);

    let second = linker.run().load(&mut context, "root").unwrap();
    assert!(
        context
            .module(first.root())
            .unwrap()
            .ptr_eq(context.module(second.root()).unwrap())
    );
    assert!(first.release(&mut context).unwrap().is_empty());
    assert_eq!(second.release(&mut context).unwrap().len(), 1);
}

#[test]
fn scan_loads_synthetic_dependency() {
    let resolver = SyntheticDependencyResolver {
        root_data: &fixtures().synthetic_root.data,
    };
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);

    let root = Linker::new()
        .resolver(resolver)
        .run()
        .load_scan_first(&mut context, "root")
        .expect("scan-first load should accept a synthetic dependency");

    assert_eq!(
        context
            .module(root.root())
            .unwrap()
            .search()
            .unwrap()
            .path()
            .file_name(),
        "scan_synthetic_root.so"
    );
    assert!(context.contains_key("root"));
    assert!(context.contains_key("dep"));

    let root_id = context
        .key_id("root")
        .and_then(|id| context.resolve_key(id).unwrap())
        .unwrap();
    let dep_module_id = context.module_id("dep").unwrap();
    assert_eq!(context.module_id("synthetic-dep"), Some(dep_module_id));
    let dep_module = context
        .module(dep_module_id)
        .expect("synthetic dependency committed");
    assert_eq!(dep_module.name(), "dep");
    assert!(dep_module.downcast_ref::<SyntheticModule>().is_some());

    let direct_deps = context.direct_deps(root_id).unwrap().collect::<Vec<_>>();
    assert_eq!(direct_deps, vec![dep_module_id]);
}

#[test]
fn unresolved_dependency_does_not_commit() {
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);

    let error = Linker::new()
        .resolver(SingleBinaryResolver {
            key: "root",
            name: "unresolved_root.so",
            data: fixtures().dependent,
        })
        .run()
        .load(&mut context, "root")
        .expect_err("missing dependency should fail before commit");

    assert!(matches!(
        error,
        Error::Linker(LinkerError::UnresolvedDependency(_))
    ));
    assert!(!context.contains_key("root"));
}

#[test]
fn publish_preserves_key_order() {
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "pending.so",
        data: fixtures().provider,
    });
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let mut run = linker.run();
    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("failed to prepare root");
    let relocated = run.relocate(prepared).expect("failed to relocate root");
    let replacement = context
        .insert(GraphModule::new(
            "root",
            SyntheticModule::empty("replacement"),
        ))
        .expect("failed to publish competing root");

    let published = relocated
        .publish(&mut context)
        .expect("distinct modules may share a lookup key");
    assert_eq!(context.module_id("root"), Some(replacement.id()));
    drop(context.release(replacement).unwrap());
    assert_eq!(context.module_id("root"), Some(published.root()));
    published.rollback(&mut context).unwrap();
}

#[test]
fn publish_rejects_occupied_source() {
    let source = ModuleSourceId::fresh();
    let load = |name| {
        Loader::new()
            .load_dylib(ElfBinary::new(name, fixtures().provider).with_source_id(source))
            .expect("failed to load provider")
    };
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "unused",
        name: "unused.so",
        data: fixtures().provider,
    });
    let mut run = linker.run();
    let prepared = run
        .prepare_mapped_root(
            &mut context,
            "pending".into(),
            load("pending.so").into_dynamic(),
        )
        .expect("failed to prepare root");
    let relocated = run.relocate(prepared).expect("failed to relocate root");
    let replacement = Relocator::new()
        .run(load("replacement.so"))
        .relocate()
        .expect("failed to relocate replacement");
    let replacement = context
        .insert(GraphModule::new("replacement", replacement))
        .expect("failed to commit replacement");

    let error = relocated
        .publish(&mut context)
        .expect_err("a source may identify only one committed module");
    let Error::Linker(LinkerError::Context { reason }) = error else {
        panic!("unexpected publication error: {error}");
    };
    assert!(matches!(
        *reason,
        LinkContextError::SourceOccupied { source: actual } if actual == source
    ));
    drop(context.release(replacement).unwrap());
}

#[test]
fn publish_rejects_reloaded_dependency() {
    let loader = Loader::new();
    let dep = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new("existing_dep.so", fixtures().provider))
                .expect("failed to load dependency"),
        )
        .relocate()
        .expect("failed to relocate dependency");
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let dep_lease = context
        .insert(GraphModule::new(DEP_KEY, dep.clone()))
        .expect("failed to insert dependency");
    let linker = Linker::new().resolver(ExistingDependencyResolver {
        root_data: fixtures().dependent,
    });
    let mut run = linker.run();
    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("failed to prepare root");
    let relocated = run.relocate(prepared).expect("failed to relocate root");

    drop(context.release(dep_lease).unwrap());
    let _new_dep = context
        .insert(GraphModule::new(DEP_KEY, dep))
        .expect("failed to reload dependency");
    let error = relocated
        .publish(&mut context)
        .expect_err("dependency generation changed before publication");
    let Error::Linker(LinkerError::Context { reason }) = error else {
        panic!("unexpected publication error: {error}");
    };
    assert!(matches!(*reason, LinkContextError::ModuleChanged { .. }));
}

#[test]
fn publish_rejects_reloaded_global_provider() {
    let source = ModuleSourceId::fresh();
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let provider = context
        .insert(GraphModule::new(
            DEP_KEY,
            load_provider_with_source("old-global.so", source),
        ))
        .unwrap();
    context.promote_global(provider.id()).unwrap();
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "global",
        name: "global.so",
        data: fixtures().global,
    });
    let mut run = linker.run();
    let prepared = run.prepare_load(&mut context, "global").unwrap();
    let relocated = run.with_observer(CustomBinding).relocate(prepared).unwrap();

    drop(context.release(provider).unwrap());
    let replacement = context
        .insert(GraphModule::new(
            DEP_KEY,
            load_provider_with_source("new-global.so", source),
        ))
        .unwrap();
    context.promote_global(replacement.id()).unwrap();

    let error = relocated
        .publish(&mut context)
        .expect_err("a new instance of the same source cannot satisfy an existing binding");
    let Error::Linker(LinkerError::Context { reason }) = error else {
        panic!("unexpected publication error: {error}");
    };
    assert!(matches!(*reason, LinkContextError::ModuleChanged { .. }));
    drop(context.release(replacement).unwrap());
}

#[test]
fn global_scope_binds_and_retains_provider() {
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let provider = context
        .insert(GraphModule::new(
            DEP_KEY,
            load_provider("global-provider.so"),
        ))
        .unwrap();
    context.promote_global(provider.id()).unwrap();
    assert_eq!(context.global_scope().modules().len(), 1);
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "global",
        name: "global.so",
        data: fixtures().global,
    });
    let loaded = linker.run().load(&mut context, "global").unwrap();
    let value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("global_value")
            .unwrap()
    };

    assert_eq!(value(), 2);
    assert!(context.release(provider).unwrap().is_empty());
    let unloaded = loaded.release(&mut context).unwrap();
    assert_eq!(
        unloaded
            .modules()
            .iter()
            .map(|entry| entry.module().name())
            .collect::<Vec<_>>(),
        ["global.so", "global-provider.so"]
    );
}

#[test]
fn unused_global_is_not_retained() {
    let global = load_provider("unused-global.so");
    let weak = global.downgrade();
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let global = context
        .insert(GraphModule::new("unused-global", global))
        .unwrap();
    context.promote_global(global.id()).unwrap();
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "root.so",
        data: fixtures().provider,
    });
    let loaded = linker.run().load(&mut context, "root").unwrap();

    drop(context.release(global).unwrap());
    assert!(weak.upgrade().is_none());
    drop(loaded.release(&mut context).unwrap());
}

#[test]
fn observer_binding_retains_provider() {
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let provider = context
        .insert(GraphModule::new(
            DEP_KEY,
            load_provider("bound-provider.so"),
        ))
        .unwrap();
    context.promote_global(provider.id()).unwrap();
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "bound",
        name: "bound.so",
        data: fixtures().global,
    });
    let loaded = linker
        .run()
        .with_observer(CustomBinding)
        .load(&mut context, "bound")
        .unwrap();

    assert!(context.release(provider).unwrap().is_empty());
    assert_eq!(loaded.release(&mut context).unwrap().modules().len(), 2);
}

#[test]
fn relocation_reads_current_globals() {
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "global",
        name: "global.so",
        data: fixtures().global,
    });
    let mut run = linker.run();
    let prepared = run.prepare_load(&mut context, "global").unwrap();
    let provider = context
        .insert(GraphModule::new(DEP_KEY, load_provider("late-global.so")))
        .unwrap();
    context.promote_global(provider.id()).unwrap();

    let relocated = run.relocate(prepared).unwrap();
    let loaded = relocated
        .publish(&mut context)
        .unwrap()
        .initialize()
        .unwrap();
    let value = unsafe {
        context
            .module(loaded.root())
            .unwrap()
            .get::<extern "C" fn() -> i32>("global_value")
            .unwrap()
    };

    assert_eq!(value(), 2);
    assert!(context.release(provider).unwrap().is_empty());
    assert_eq!(loaded.release(&mut context).unwrap().modules().len(), 2);
}

#[test]
fn publish_rejects_reloaded_root() {
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "reloaded_root.so",
        data: fixtures().provider,
    });
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let mut run = linker.run();
    let loaded = run.load(&mut context, "root").unwrap();
    let prepared = run.prepare_load(&mut context, "root").unwrap();
    let relocated = run.relocate(prepared).unwrap();

    loaded.release(&mut context).unwrap();
    let replacement = run.load(&mut context, "root").unwrap();
    let error = relocated
        .publish(&mut context)
        .expect_err("reloaded root must invalidate the prepared transaction");
    let Error::Linker(LinkerError::Context { reason }) = error else {
        panic!("unexpected publication error: {error}");
    };
    assert!(matches!(*reason, LinkContextError::ModuleChanged { .. }));
    replacement.release(&mut context).unwrap();
}

#[test]
#[cfg(any(
    feature = "use-syscall",
    all(any(target_os = "linux", target_os = "android"), feature = "libc")
))]
fn loads_dynamic_exec() {
    let fixtures = fixtures();

    for scan_first in [false, true] {
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
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
            linker.run().load_scan_first(&mut context, "root")
        } else {
            linker.run().load(&mut context, "root")
        }
        .expect("linker should accept dynamic ET_EXEC roots");

        assert!(context.contains_key("root"));
        assert!(context.contains_key(DEP_KEY));
    }
}

#[test]
fn existing_root_records_request_key() {
    for scan_first in [false, true] {
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let linker = Linker::new().resolver(SingleBinaryResolver {
            key: "canonical",
            name: "canonical.so",
            data: fixtures().provider,
        });
        let loaded = if scan_first {
            linker.run().load_scan_first(&mut context, "canonical")
        } else {
            linker.run().load(&mut context, "canonical")
        }
        .expect("failed to load canonical root");

        let linker = Linker::new().resolver(ExistingRootResolver {
            requested: "alias",
            existing: "canonical",
        });
        let alias = if scan_first {
            linker.run().load_scan_first(&mut context, "alias")
        } else {
            linker.run().load(&mut context, "alias")
        }
        .expect("failed to reuse existing root");

        assert_eq!(alias.root(), loaded.root());
        assert_eq!(context.module_id("alias"), Some(loaded.root()));

        let linker = Linker::new().resolver(ExistingRootResolver {
            requested: "alias",
            existing: "missing",
        });
        let reused = if scan_first {
            linker.run().load_scan_first(&mut context, "alias")
        } else {
            linker.run().load(&mut context, "alias")
        }
        .expect("recorded request key should bypass the resolver");
        assert_eq!(reused.root(), loaded.root());
    }
}

#[test]
fn existing_requires_committed_key() {
    let resolver = ExistingRootResolver {
        requested: "alias",
        existing: "missing",
    };
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);

    let error = Linker::new()
        .resolver(resolver)
        .run()
        .load_scan_first(&mut context, "alias")
        .unwrap_err();

    assert!(matches!(
        error,
        Error::Linker(LinkerError::Resolver {
            reason: LinkResolverError::ExistingKeyMissing
        })
    ));
}

#[test]
fn repeated_loads_acquire_the_root() {
    let linker = Linker::new().resolver(dependency_resolver("acquired_root.so", "acquired_dep.so"));
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);

    let first = linker
        .run()
        .load(&mut context, "root")
        .expect("first load should succeed");
    let second = linker
        .run()
        .load(&mut context, "root")
        .expect("existing root should be acquired");

    assert_eq!(first.root(), second.root());
    assert_eq!(first.modules().len(), 2);
    assert!(second.modules().is_empty());
    assert!(first.release(&mut context).unwrap().is_empty());
    assert!(context.contains_key("root"));
    assert!(context.contains_key(DEP_KEY));

    let unloaded = second.release(&mut context).unwrap();
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
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
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

    let unloaded = loaded
        .release(&mut context)
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
    impl LinkerObserver for PlanningObserver {
        fn on_relocation(
            &mut self,
            event: &mut LinkerRelocationEvent<()>,
        ) -> elf_loader::Result<()> {
            self.0.borrow_mut().push(event.raw().name().to_string());
            Ok(())
        }
    }

    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let linker = Linker::new().resolver(resolver);
    let loaded = linker
        .run()
        .with_observer(PlanningObserver(Rc::clone(&planned)))
        .load(&mut context, "root")
        .expect("failed to load root with dependency");

    assert_eq!(
        *planned.borrow(),
        vec!["dep.so".to_string(), "root.so".to_string()],
        "relocation should still run in dependency-first order"
    );
    assert!(context.contains_key("root"));
    assert!(context.contains_key(DEP_KEY));
    drop(loaded.release(&mut context).unwrap());
}

#[test]
fn phased_load_initializes_dependencies_first() {
    let resolver = dependency_resolver("phased_root.so", "phased_dep.so");
    let linker = Linker::new().resolver(resolver);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut run = linker
        .run()
        .with_observer(InitRecorder::new(Arc::clone(&calls)));
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);

    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should resolve the module group");
    assert!(!context.contains_key("root"));
    assert!(!context.contains_key(DEP_KEY));

    let relocated = run
        .relocate(prepared)
        .expect("relocation should succeed without a context borrow");
    assert!(!context.contains_key("root"));
    assert!(!context.contains_key(DEP_KEY));

    let published = relocated
        .publish(&mut context)
        .expect("publish should expose the relocated group");
    assert!(context.contains_key("root"));
    assert!(context.contains_key(DEP_KEY));
    assert!(
        !context
            .module(published.root())
            .unwrap()
            .state()
            .is_initialized()
    );

    let result = published
        .initialize()
        .expect("initialization should succeed");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["phased_dep.so".to_string(), "phased_root.so".to_string()]
    );
    assert!(
        context
            .module(result.root())
            .unwrap()
            .state()
            .is_initialized()
    );

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
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should succeed");
    let relocated = run.relocate(prepared).expect("relocation should succeed");
    let mut other_context = LinkContext::<()>::new(DomainId::PROCESS);

    let err = relocated
        .publish(&mut other_context)
        .expect_err("publish must reject another context");
    assert!(matches!(
        err,
        Error::Linker(LinkerError::Context {
            reason,
        }) if matches!(*reason, LinkContextError::ContextMismatch { .. })
    ));
    assert!(!other_context.contains_key("root"));
}

#[test]
fn rollback_rejects_other_context() {
    let linker = Linker::new().resolver(SingleBinaryResolver {
        key: "root",
        name: "context_bound.so",
        data: fixtures().provider,
    });
    let mut run = linker.run();
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let prepared = run
        .prepare_load(&mut context, "root")
        .expect("prepare should succeed");
    let relocated = run.relocate(prepared).expect("relocation should succeed");
    let published = relocated
        .publish(&mut context)
        .expect("publish should succeed");
    let mut other_context = LinkContext::<()>::new(DomainId::PROCESS);

    let error = published
        .rollback(&mut other_context)
        .expect_err("rollback must reject another context");
    assert!(matches!(
        error,
        Error::Linker(LinkerError::Context {
            reason,
        }) if matches!(*reason, LinkContextError::ContextMismatch { .. })
    ));
    assert!(context.contains_key("root"));
    assert!(!other_context.contains_key("root"));
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
    let mut context = LinkContext::<()>::new(DomainId::PROCESS);
    let prepared = run.prepare_load(&mut context, "root").unwrap();
    let relocated = run.relocate(prepared).unwrap();
    let published = relocated.publish(&mut context).unwrap();

    let failed = published.initialize().expect_err("initializer should fail");
    assert!(context.contains_key("root"));
    assert!(failed.error().to_string().contains("initializer failed"));

    let error = failed.rollback(&mut context);
    assert!(error.to_string().contains("initializer failed"));
    assert!(!context.contains_key("root"));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["failing_init.so", "fini:failing_init.so"]
    );
}
