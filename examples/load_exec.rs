#[path = "support/mod.rs"]
mod fixture_support;

use elf_loader::{Loader, Result};

const LOADER: Loader = Loader::new();

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let exec_path = fixture_support::ensure_native_exec();

    let exec = LOADER.load_exec(
        exec_path
            .to_str()
            .expect("fixture path must be valid UTF-8"),
    )?;
    println!("Loaded executable: {}", exec.name());
    println!("Entry point: 0x{:x}", exec.entry());
    println!("Base address: {}", exec.base());

    Ok(())
}
