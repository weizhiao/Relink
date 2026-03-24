#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, Result};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new();

    let exec_path = fixture_support::ensure_exec_a();

    let exec = loader.load_exec(
        exec_path
            .to_str()
            .expect("fixture path must be valid UTF-8"),
    )?;
    println!("Loaded executable: {}", exec.name());
    println!("Entry point: 0x{:x}", exec.entry());
    println!("Base address: 0x{:x}", exec.base());

    Ok(())
}
