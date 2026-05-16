#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, Result, loader::LoadHookContext};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new().with_hook(|ctx: &LoadHookContext| {
        println!("Loading segment for {}:", ctx.path());
        println!("  Type: {:?}", ctx.phdr().program_type());
        println!("  Offset: 0x{:x}", ctx.phdr().p_offset());
        println!("  Vaddr: 0x{:x}", ctx.phdr().p_vaddr());
        println!("  Filesz: 0x{:x}", ctx.phdr().p_filesz());
        println!("  Memsz: 0x{:x}", ctx.phdr().p_memsz());
        println!("  Flags: {:?}", ctx.phdr().flags());
        Ok(())
    });

    let fixtures = fixture_support::ensure_all();
    let _lib = loader
        .load_dylib(fixtures.liba_str())?
        .relocator()
        .relocate()?;
    println!("Loaded with segment hook.");

    Ok(())
}
