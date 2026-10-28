use elf_loader::{LinkContext, Linker, input::PathBuf, linker::SearchPathResolver};
use std::ffi::c_int;

const LIBRARY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/example-library/libexample.so"
);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let mut context = LinkContext::for_process();
    let loaded = Linker::new()
        .with_resolver(SearchPathResolver::new())
        .run()
        .load(&mut context, PathBuf::from(LIBRARY))?;

    let module = context.module(loaded.root())?;
    // SAFETY: examples/library/example.c defines int example_add(int, int).
    let value = unsafe {
        let add = module
            .get::<unsafe extern "C" fn(c_int, c_int) -> c_int>("example_add")?
            .ok_or("missing example_add")?;
        add(2, 3)
    };
    println!(
        "loaded {} with {} new modules; example_add(2, 3) = {value}",
        module.name().escape_ascii(),
        loaded.modules().len()
    );
    drop(loaded.release(&mut context)?);
    Ok(())
}
