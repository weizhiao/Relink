use elf_loader::{AddressSpaceId, Domain, Loader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: load_exec <ELF executable>")?;
    let exec = Loader::new()
        .run(Domain::native(AddressSpaceId::PROCESS))
        .load_exec(path)?;

    println!("Loaded executable: {}", exec.name().escape_ascii());
    println!("Entry point: 0x{:x}", exec.entry());
    println!("Base address: {}", exec.base());
    Ok(())
}
