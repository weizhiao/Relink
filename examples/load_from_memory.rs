use elf_loader::{AddressSpaceId, Domain, Loader, Relocator, input::ElfBinary};
use std::ffi::c_int;

const LIBRARY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/example-library/libexample.so"
);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let bytes = std::fs::read(LIBRARY)?;
    let raw = Loader::new()
        .run(Domain::native(AddressSpaceId::PROCESS))
        .load_dylib(ElfBinary::new(LIBRARY, &bytes))?;
    let library = Relocator::new().run(raw).relocate()?;

    // SAFETY: examples/library/example.c defines int example_add(int, int).
    let value = unsafe {
        let add = library
            .get::<unsafe extern "C" fn(c_int, c_int) -> c_int>("example_add")?
            .ok_or("missing example_add")?;
        add(2, 3)
    };
    println!("loaded {} bytes; example_add(2, 3) = {value}", bytes.len());
    Ok(())
}
