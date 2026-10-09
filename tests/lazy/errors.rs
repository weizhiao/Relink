use elf_loader::{
    Error, Loader,
    error::{LazyBindingError, RelocationError},
    input::ElfBinary,
    relocation::{BindingMode, Relocator},
};

use crate::fixture::fixtures;

#[test]
fn requires_binder() {
    for (configured, override_mode) in [
        (BindingMode::Default, Some(BindingMode::Lazy)),
        (BindingMode::Lazy, None),
        (BindingMode::Eager, Some(BindingMode::Lazy)),
    ] {
        let relocator = Relocator::new().binding(configured);
        let run = relocator.run(
            Loader::new()
                .load_dylib(ElfBinary::new("consumer.so", &fixtures().consumer))
                .expect("failed to load lazy-binding consumer"),
        );
        let run = match override_mode {
            Some(binding) => run.binding(binding),
            None => run,
        };
        let error = run
            .relocate()
            .expect_err("lazy relocation without a binder should fail");

        assert!(matches!(
            error,
            Error::Relocation(RelocationError::LazyBinding(
                LazyBindingError::MissingBinder
            ))
        ));
    }
}
