use elf_loader::{Loader, Result};

#[allow(dead_code)]
#[derive(Debug)]
struct MyContext {
    load_time: std::time::SystemTime,
    custom_id: u32,
}

impl Default for MyContext {
    fn default() -> Self {
        Self {
            load_time: std::time::SystemTime::now(),
            custom_id: 0,
        }
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new().with_context_loader(|ctx| {
        println!("Loading user data for: {}", ctx.name());
        MyContext {
            load_time: std::time::SystemTime::now(),
            custom_id: 42,
        }
    });

    let lib = loader
        .load_dylib("target/liba.so")?
        .relocator()
        .relocate()?;

    let context = lib.user_data();
    println!("Loaded {:?} with context: {:?}", lib.name(), context);

    Ok(())
}
