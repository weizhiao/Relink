#![cfg(not(windows))]

mod fixture;
#[path = "../fixture_build/mod.rs"]
mod fixture_build;
use elf_loader::{
    Error, LinkContext, Linker, Loader, Module, Relocator,
    arch::NativeArch,
    error::{LinkContextError, LinkerError},
    image::{LoadedCore, ModuleCapability, SyntheticModule},
    input::ElfBinary,
    linker::{
        KeyResolver, ResolvedKey, RootRequest, VisibleModule,
        scan::{DataPass, LinkPass, LinkPassPlan, Materialization, PassScopeMode},
    },
    memory::{RegionAccess, VmAddr},
    observer::{
        DynamicRelocatedEvent, LinkerObserver, LinkerRelocationEvent, LoadObserver,
        RelocationObserver,
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
    boxed::Box,
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
impl LinkerObserver<&'static str, ()> for InitRecorder {}

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
        assert_eq!(req.needed(), DEP_KEY);
        assert!(req.contains_key(&DEP_KEY));
        Ok(ResolvedKey::existing(DEP_KEY))
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

impl LoadObserver for StaticVisibleModule {}
impl RelocationObserver for StaticVisibleModule {}

impl LinkerObserver<&'static str, ()> for StaticVisibleModule {
    fn contains_visible<Q>(&self, key: &Q) -> bool
    where
        &'static str: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        <&'static str as std::borrow::Borrow<Q>>::borrow(&self.key) == key
    }

    fn visible_module<Q>(&self, key: &Q) -> Option<VisibleModule<&'static str>>
    where
        &'static str: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        (<&'static str as std::borrow::Borrow<Q>>::borrow(&self.key) == key)
            .then(|| VisibleModule::new(self.module.clone(), self.direct_deps.clone()))
    }
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

mod loading;
mod planning;
#[cfg(all(not(windows), any(feature = "libc", feature = "use-syscall")))]
mod search_path;
