use elf_loader::{
    Error, Loader,
    error::{LazyBindingError, RelocationError},
    input::ElfBinary,
    relocation::Relocator,
};

use crate::fixture::fixtures;

#[test]
fn requires_binder() {
    let error = Relocator::new()
        .run(
            Loader::new()
                .load_dylib(ElfBinary::new("consumer.so", &fixtures().consumer))
                .expect("failed to load lazy-binding consumer"),
        )
        .lazy()
        .relocate()
        .expect_err("lazy relocation without a binder should fail");

    assert!(matches!(
        error,
        Error::Relocation(RelocationError::LazyBinding(
            LazyBindingError::MissingBinder
        ))
    ));
}
