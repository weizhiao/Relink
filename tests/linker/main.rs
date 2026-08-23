#![cfg(not(windows))]

mod fixture;
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
use elf_loader::{
    Error, GraphModule, LinkContext, Linker, Loader, Module, Relocator,
    arch::NativeArch,
    error::{LinkContextError, LinkResolverError, LinkerError},
    image::{LoadedCore, ModuleCapability, SyntheticModule, SyntheticSymbol},
    input::{ElfBinary, ModuleSourceId},
    linker::{
        KeyResolver, ResolveInput, ResolveRequest, ResolvedKey,
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

struct ExistingRootResolver {
    requested: &'static str,
    existing: &'static str,
}

struct ModuleDependencyResolver {
    root_data: &'static [u8],
    dep: LoadedCore<()>,
}

struct ExistingDependencyResolver {
    root_data: &'static [u8],
}

struct SyntheticDependencyResolver {
    root_data: &'static [u8],
}

struct SyntheticRootResolver;

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
                Ok(ResolvedKey::load(
                    self.key,
                    ElfBinary::new(self.name, self.data),
                ))
            }
            ResolveInput::Dependency { .. } => Err(req.unresolved()),
        }
    }
}

impl KeyResolver for ExistingRootResolver {
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
                assert_eq!(*root, self.requested);
                Ok(ResolvedKey::existing(self.existing))
            }
            ResolveInput::Dependency { .. } => {
                panic!("existing scan root should not resolve dependencies")
            }
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
                Ok(ResolvedKey::load(
                    "root",
                    ElfBinary::new("visible_root.so", self.root_data),
                ))
            }
            ResolveInput::Dependency { needed } => {
                assert_eq!(*needed, DEP_KEY);
                Ok(ResolvedKey::module(DEP_KEY, self.dep.clone(), Vec::new()))
            }
        }
    }
}

impl KeyResolver for ExistingDependencyResolver {
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
                Ok(ResolvedKey::load(
                    "root",
                    ElfBinary::new("existing_dep_root.so", self.root_data),
                ))
            }
            ResolveInput::Dependency { needed } => {
                assert_eq!(*needed, DEP_KEY);
                Ok(ResolvedKey::existing(DEP_KEY))
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
                Ok(ResolvedKey::load(
                    "root",
                    ElfBinary::new("scan_synthetic_root.so", self.root_data),
                ))
            }
            ResolveInput::Dependency { needed } => {
                assert_eq!(*needed, "dep");
                Ok(ResolvedKey::module(
                    "synthetic-dep",
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
            ResolveInput::Root { root } => Ok(ResolvedKey::module(
                *root,
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
