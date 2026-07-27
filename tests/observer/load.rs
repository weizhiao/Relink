use elf_loader::{
    Loader,
    arch::NativeArch,
    input::ElfBinary,
    memory::RegionAccess,
    observer::{AfterDynamicLoadEvent, BeforeLoadEvent, LoadObserver},
    tls::TlsResolver,
};

#[derive(Default)]
struct LoadState {
    before: bool,
    after: bool,
}

struct Recorder;

impl LoadObserver<LoadState> for Recorder {
    fn on_before_load(
        &mut self,
        mut event: BeforeLoadEvent<'_, LoadState>,
    ) -> elf_loader::Result<()> {
        assert_eq!(event.path().file_name(), "observed.so");
        assert_eq!(
            event.reader().len(),
            crate::fixture::fixtures().provider.len()
        );
        assert!(event.is_dynamic());
        event.user_data_mut().before = true;
        Ok(())
    }

    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        mut event: AfterDynamicLoadEvent<'_, LoadState, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let raw = event.raw_mut();
        let state = raw
            .user_data_mut()
            .expect("load observer should have unique access to user data");
        assert!(state.before);
        state.after = true;
        Ok(())
    }
}

#[test]
fn observes_dynamic_load() {
    let bytes = &crate::fixture::fixtures().provider;
    let raw = Loader::new()
        .with_data::<LoadState>()
        .run()
        .with_observer(Recorder)
        .load_dylib(ElfBinary::new("observed.so", bytes))
        .expect("observed dynamic image should load");

    assert!(raw.user_data().before);
    assert!(raw.user_data().after);
}
