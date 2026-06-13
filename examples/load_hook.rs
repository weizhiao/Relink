#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    arch::NativeArch,
    observer::{BeforeDynamicLoadEvent, LoadObserver},
    relocation::RelocationArch,
};

struct PrintObserver;

impl LoadObserver for PrintObserver {
    fn on_before_dynamic_load(
        &mut self,
        event: BeforeDynamicLoadEvent<'_, (), <NativeArch as RelocationArch>::Layout>,
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

    let mut loader = Loader::new().with_observer(PrintObserver);

    let fixtures = fixture_support::ensure_all();
    let _lib = loader
        .load_dylib(fixtures.liba_str())?
        .relocator()
        .relocate()?;
    println!("Loaded with segment hook.");

    Ok(())
}
