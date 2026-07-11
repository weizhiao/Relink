#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    arch::NativeArch,
    observer::{BeforeLoadEvent, LoadObserver},
    relocation::{RelocationArch, Relocator},
};

const LOADER: Loader = Loader::new();

struct PrintObserver;

impl LoadObserver for PrintObserver {
    fn on_before_load(
        &mut self,
        event: BeforeLoadEvent<'_, (), <NativeArch as RelocationArch>::Layout>,
    ) -> Result<()> {
        println!("Loading dynamic image for {}:", event.path());
        for phdr in event.phdrs() {
            println!("  Type: {:?}", phdr.program_type());
            println!("    Offset: 0x{:x}", phdr.p_offset());
            println!("    Vaddr: {}", phdr.p_vaddr());
            println!("    Filesz: 0x{:x}", phdr.p_filesz());
            println!("    Memsz: 0x{:x}", phdr.p_memsz());
            println!("    Flags: {:?}", phdr.flags());
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let fixtures = fixture_support::ensure_all();
    let _lib = Relocator::new()
        .run(
            LOADER
                .run()
                .with_observer(PrintObserver)
                .load_dylib(fixtures.liba_str())?,
        )
        .relocate()?;
    println!("Loaded with segment hook.");

    Ok(())
}
