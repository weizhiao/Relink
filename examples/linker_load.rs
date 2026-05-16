#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Result,
    input::PathBuf,
    linker::{LinkContext, Linker},
};

fn main() -> Result<()> {
    let fixtures = fixture_support::ensure_all();
    let mut context: LinkContext<PathBuf, ()> = LinkContext::new();

    let loaded = Linker::new()
        .resolver(fixture_support::search_path_resolver())
        .load(&mut context, PathBuf::from(fixtures.libc_str()))?;

    let c = unsafe { loaded.get::<fn() -> i32>("c").unwrap() };
    let value = c();
    assert_eq!(value, 3);
    println!(
        "loaded {} with {} committed modules; c() = {}",
        loaded.name(),
        loaded.committed().len(),
        value
    );

    Ok(())
}
