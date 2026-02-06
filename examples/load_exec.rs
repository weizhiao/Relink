use elf_loader::{Loader, Result};

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new();

    let exec_path = "target/exec_a";

    let exec = loader.load_exec(exec_path)?;
    println!("Loaded executable: {}", exec.name());
    println!("Entry point: 0x{:x}", exec.entry());
    println!("Base address: 0x{:x}", exec.base());

    Ok(())
}
