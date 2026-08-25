use elf_loader::{
    Loader, Module, Relocator,
    arch::NativeArch,
    input::ElfBinary,
    memory::{RegionAccess, VmAddr},
    observer::{
        DynamicRelocatedEvent, HandleResult, RelocationEvent, RelocationObserver,
        SymbolBindingEvent,
    },
    tls::TlsResolver,
};
use std::sync::{Arc, Mutex};

const SYMBOLS: [&str; 3] = ["MESSAGE", "provider_value", "trace"];
const PRE_SYMBOL: &str = "trace";

extern "C" fn override_value() -> i32 {
    41
}

#[derive(Default)]
struct BindingState {
    pre: Vec<String>,
    bindings: Vec<String>,
}

struct BindingRecorder(Arc<Mutex<BindingState>>);

impl RelocationObserver for BindingRecorder {
    fn on_relocation_pre<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
        H,
    >(
        &mut self,
        event: &mut RelocationEvent<'_, D, NativeArch, R, Tls, H>,
    ) -> elf_loader::Result<HandleResult> {
        let symbol = event
            .relocation_symbol()
            .expect("GOT relocation should reference a symbol");
        assert_eq!(event.lib().name(), "consumer.so");
        assert_eq!(event.scope().len(), 1);
        assert!(event.lazy().is_none());
        assert!(SYMBOLS.contains(&symbol.name()));
        assert_eq!(event.symbol(event.rel().r_symbol()).name(), symbol.name());
        assert!(event.bind_symdef(event.rel().r_symbol()).is_some());
        self.0.lock().unwrap().pre.push(symbol.name().to_string());
        Ok(HandleResult::Unhandled)
    }

    fn on_symbol_binding<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
    >(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        assert_eq!(event.core().name(), "consumer.so");
        assert!(event.rel().is_some());
        assert!(event.symbol().is_undef());
        assert!(SYMBOLS.contains(&event.symbol_name()));
        assert!(event.resolved_addr().is_some());
        if event.symbol_name() == "provider_value" {
            event.set_resolved_addr(VmAddr::from_ptr(override_value as *const ()));
        }
        self.0
            .lock()
            .unwrap()
            .bindings
            .push(event.symbol_name().to_string());
        Ok(())
    }
}

#[test]
fn observes_symbol_binding() {
    let fixtures = crate::fixture::fixtures();
    let loader = Loader::new();
    let provider = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new("provider.so", &fixtures.provider))
                .expect("failed to load symbol provider"),
        )
        .relocate()
        .expect("failed to relocate symbol provider");
    let state = Arc::new(Mutex::new(BindingState::default()));
    let _loaded = Relocator::new()
        .run(
            loader
                .load_dylib(ElfBinary::new("consumer.so", &fixtures.dependent))
                .expect("failed to load symbol consumer"),
        )
        .modules([&provider])
        .observer(BindingRecorder(Arc::clone(&state)))
        .relocate()
        .expect("failed to relocate symbol consumer");

    #[cfg(any(
        feature = "use-syscall",
        all(any(target_os = "linux", target_os = "android"), feature = "libc")
    ))]
    {
        let dependent = unsafe { _loaded.get::<extern "C" fn() -> i32>("dependent_value") }
            .expect("missing symbol");
        assert_eq!(dependent(), 42);
    }

    let mut state = state.lock().unwrap();
    state.pre.sort();
    state.bindings.sort();
    assert_eq!(state.pre, SYMBOLS);
    assert_eq!(state.bindings, SYMBOLS);
}

#[derive(Default)]
struct FallbackState {
    pre: Vec<String>,
    post: Vec<String>,
}

struct FallbackRecorder(Arc<Mutex<FallbackState>>);

impl RelocationObserver for FallbackRecorder {
    fn on_relocation_pre<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
        H,
    >(
        &mut self,
        event: &mut RelocationEvent<'_, D, NativeArch, R, Tls, H>,
    ) -> elf_loader::Result<HandleResult> {
        let symbol = event
            .relocation_symbol()
            .expect("GOT relocation should reference a symbol");
        assert_eq!(event.lib().name(), "unresolved.so");
        assert!(event.scope().is_empty());
        assert!(event.lazy().is_none());
        assert!(event.bind_symdef(event.rel().r_symbol()).is_none());
        self.0.lock().unwrap().pre.push(symbol.name().to_string());
        Ok(if symbol.name() == PRE_SYMBOL {
            HandleResult::Handled
        } else {
            HandleResult::Unhandled
        })
    }

    fn on_relocation_post<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
        H,
    >(
        &mut self,
        event: &mut RelocationEvent<'_, D, NativeArch, R, Tls, H>,
    ) -> elf_loader::Result<HandleResult> {
        let symbol = event
            .relocation_symbol()
            .expect("GOT relocation should reference a symbol");
        assert_ne!(symbol.name(), PRE_SYMBOL);
        self.0.lock().unwrap().post.push(symbol.name().to_string());
        Ok(HandleResult::Handled)
    }
}

#[test]
fn handles_relocation_hooks() {
    let bytes = &crate::fixture::fixtures().dependent;
    let state = Arc::new(Mutex::new(FallbackState::default()));

    Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new("unresolved.so", bytes))
                .expect("failed to load unresolved image"),
        )
        .observer(FallbackRecorder(Arc::clone(&state)))
        .relocate()
        .expect("observer should handle unresolved symbols");

    let mut state = state.lock().unwrap();
    state.pre.sort();
    state.post.sort();
    assert_eq!(state.pre, SYMBOLS);
    assert_eq!(state.post, ["MESSAGE", "provider_value"]);
}

#[derive(Default)]
struct LifecycleState {
    relocated: bool,
    initialized: Vec<String>,
}

struct LifecycleRecorder(Arc<Mutex<LifecycleState>>);

impl RelocationObserver for LifecycleRecorder {
    fn on_dynamic_relocated<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
    >(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        assert_eq!(event.name(), "deferred.so");
        assert_eq!(event.path().file_name(), "deferred.so");
        assert_eq!(event.core().name(), event.name());
        assert_ne!(event.base(), VmAddr::null());
        assert!(event.core().segments().contains_addr(event.dynamic_addr()));
        self.0.lock().unwrap().relocated = true;

        let state = Arc::clone(&self.0);
        event.lifecycle_mut().set_init_hook(move |event| {
            state
                .lock()
                .unwrap()
                .initialized
                .push(event.name().to_string());
            event.lifecycle_mut().clear();
            Ok(())
        });
        Ok(())
    }
}

#[test]
fn defers_initialization() {
    let bytes = &crate::fixture::fixtures().provider;
    let raw = Loader::new()
        .load_dylib(ElfBinary::new("deferred.so", bytes))
        .expect("dynamic image should load");
    let state = Arc::new(Mutex::new(LifecycleState::default()));
    let loaded = Relocator::new()
        .defer_init()
        .run(raw)
        .observer(LifecycleRecorder(Arc::clone(&state)))
        .relocate()
        .expect("dynamic image should relocate without initialization");

    assert!(!loaded.state().is_initialized());
    {
        let state = state.lock().unwrap();
        assert!(state.relocated);
        assert!(state.initialized.is_empty());
    }

    loaded
        .initialize()
        .expect("deferred initialization should succeed");
    assert!(loaded.state().is_initialized());
    assert_eq!(
        state.lock().unwrap().initialized.as_slice(),
        &["deferred.so"]
    );
}
