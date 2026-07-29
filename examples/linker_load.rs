#[path = "support/mod.rs"]
mod fixture_support;

use elf_loader::{LinkContext, Linker, Module, Result, input::PathBuf, runtime::DomainId};

fn main() -> Result<()> {
    let fixtures = fixture_support::ensure_all();
    let mut context: LinkContext<PathBuf, ()> = LinkContext::new(DomainId::PROCESS);

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .load(&mut context, PathBuf::from(fixtures.leaf_str()))?;

    let leaf_value = unsafe { loaded.get::<extern "C" fn() -> i32>("leaf_value").unwrap() };
    let value = leaf_value();
    assert_eq!(value, 3);
    println!(
        "loaded {} with {} committed modules; leaf_value() = {}",
        loaded.name(),
        loaded.modules().len(),
        value
    );

    Ok(())
}
