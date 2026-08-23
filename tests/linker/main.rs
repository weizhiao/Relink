#![cfg(not(windows))]

mod fixture;
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
use elf_loader::{
    Error, GraphModule, LinkContext, Linker, Loader, Module, Relocator,
    arch::NativeArch,
    error::{LinkContextError, LinkerError},
    image::{ElfModule, LoadedCore, ModuleCapability, SyntheticModule, SyntheticSymbol},
    input::{ElfBinary, ModuleSourceId},
    linker::{
        KeyResolver, ResolveInput, ResolveRequest, ResolvedDependency, ResolvedKey,
        scan::{DataPass, LinkPass, LinkPassPlan, Materialization, PassScopeMode},
    },
    memory::{RegionAccess, VmAddr},
    observer::{
        DynamicRelocatedEvent, HandleResult, LinkerObserver, LinkerRelocationEvent, LoadObserver,
        RelocationEvent, RelocationObserver,
    },
    runtime::DomainId,
    tls::TlsResolver,
};
#[cfg(target_arch = "x86_64")]
use elf_loader::{
    linker::scan::{ArenaDescriptor, ArenaSharing, MemoryClass, ReorderPass},
    os::PageSize,
};
use gen_elf::{Arch, DylibWriter, ElfWriteOutput, ElfWriterConfig};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
    vec::Vec,
};

const DEP_KEY: &str = "libprovider.so";

struct SingleBinaryResolver {
    key: &'static str,
    name: &'static str,
    data: &'static [u8],
}

struct ModuleDependencyResolver {
    root_data: &'static [u8],
    dep: LoadedCore<()>,
}

struct SyntheticDependencyResolver {
    root_data: &'static [u8],
}

struct SyntheticRootResolver;

struct ResolvedGraphResolver;

extern "C" fn synthetic_value() -> i32 {
    42
}

struct InitRecorder {
    calls: Arc<Mutex<Vec<String>>>,
    fail: bool,
    record_fini: bool,
}

impl InitRecorder {
    fn new(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            calls,
            fail: false,
            record_fini: false,
        }
    }

    fn failing(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            calls,
            fail: true,
            record_fini: true,
        }
    }
}

impl LoadObserver for InitRecorder {}
impl LinkerObserver for InitRecorder {}

impl RelocationObserver for InitRecorder {
    fn on_dynamic_relocated<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
    >(
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
        if self.record_fini {
            let calls = Arc::clone(&self.calls);
            event.lifecycle_mut().set_fini_hook(move |event| {
                calls.lock().unwrap().push(format!("fini:{}", event.name()));
                event.lifecycle_mut().clear();
                Ok(())
            });
        }
        Ok(())
    }
}

impl KeyResolver for SingleBinaryResolver {
    type Root = &'static str;

    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg>> {
        match req.input() {
            ResolveInput::Root { root } => {
                assert_eq!(*root, self.key);
                Ok(ResolvedKey::load(ElfBinary::new(self.name, self.data)))
            }
            ResolveInput::Dependency { .. } => Err(req.unresolved()),
        }
    }
}

impl KeyResolver for ModuleDependencyResolver {
    type Root = &'static str;

    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg>> {
        match req.input() {
            ResolveInput::Root { root } => {
                assert_eq!(*root, "root");
                Ok(ResolvedKey::load(ElfBinary::new(
                    "visible_root.so",
                    self.root_data,
                )))
            }
            ResolveInput::Dependency { needed } => {
                assert_eq!(*needed, DEP_KEY);
                Ok(ResolvedKey::module(self.dep.clone(), Vec::new()))
            }
        }
    }
}

impl KeyResolver for SyntheticDependencyResolver {
    type Root = &'static str;

    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg>> {
        match req.input() {
            ResolveInput::Root { root } => {
                assert_eq!(*root, "root");
                Ok(ResolvedKey::load(ElfBinary::new(
                    "scan_synthetic_root.so",
                    self.root_data,
                )))
            }
            ResolveInput::Dependency { needed } => {
                assert_eq!(*needed, "dep");
                Ok(ResolvedKey::module(
                    SyntheticModule::empty("dep"),
                    Vec::new(),
                ))
            }
        }
    }
}

impl KeyResolver for SyntheticRootResolver {
    type Root = &'static str;

    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg>> {
        match req.input() {
            ResolveInput::Root { .. } => Ok(ResolvedKey::module(
                SyntheticModule::new(
                    "synthetic-root",
                    [SyntheticSymbol::function(
                        "synthetic_value",
                        synthetic_value as *const (),
                    )],
                ),
                Vec::new(),
            )),
            ResolveInput::Dependency { .. } => {
                unreachable!("synthetic root has no dependencies")
            }
        }
    }
}

impl KeyResolver for ResolvedGraphResolver {
    type Root = &'static str;

    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, &'static str>,
    ) -> elf_loader::Result<ResolvedKey<'cfg>> {
        match req.input() {
            ResolveInput::Root { root } => Ok(ResolvedKey::module(
                SyntheticModule::empty(*root),
                [ResolvedDependency::new(
                    "dep",
                    ResolvedKey::module(SyntheticModule::empty("dep"), Vec::new()),
                )],
            )),
            ResolveInput::Dependency { .. } => {
                unreachable!("the synthetic graph is already resolved")
            }
        }
    }
}

struct TestPass<F>(F);

impl<S, F> LinkPass<S> for TestPass<F>
where
    S: PassScopeMode,
    F: for<'a> FnMut(&mut LinkPassPlan<'a, S>) -> elf_loader::Result<()>,
{
    fn run(&mut self, plan: &mut LinkPassPlan<'_, S>) -> elf_loader::Result<()> {
        (self.0)(plan)
    }
}

mod loading;
mod planning;
#[cfg(all(not(windows), any(feature = "libc", feature = "use-syscall")))]
mod search_path;
