#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    arch::NativeArch,
    memory::RegionAccess,
    relocation::{HandleResult, RelocationContext, RelocationHandler},
    tls::TlsResolver,
};

struct MyRelocHandler;

fn my_print(s: &str) {
    println!("Caught by MyRelocHandler: {}", s);
}

impl RelocationHandler for MyRelocHandler {
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>, H>(
        &self,
        ctx: &RelocationContext<'_, D, NativeArch, R, Tls, H>,
    ) -> Result<HandleResult> {
        let Some(symbol) = ctx.relocation_symbol() else {
            return Ok(HandleResult::Unhandled);
        };

        if symbol.name() == "print" {
            let target_addr = (ctx.lib().base() + ctx.rel().r_offset()).get() as *mut usize;
            println!(
                "Relocating 'print' for {} at {:p}",
                ctx.lib().name(),
                target_addr
            );
            unsafe { *target_addr = my_print as *const () as usize };
            return Ok(HandleResult::Handled);
        }

        Ok(HandleResult::Unhandled)
    }
}

fn main() -> Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "trace") };
    env_logger::init();

    let mut loader = Loader::new();
    let fixtures = fixture_support::ensure_all();

    let _liba = loader
        .load_dylib(fixtures.liba_str())?
        .relocator()
        .pre_handler(MyRelocHandler)
        .relocate()?;
    let libb = loader
        .load_dylib(fixtures.libb_str())?
        .relocator()
        .pre_handler(MyRelocHandler)
        .scope([&_liba])
        .relocate()?;

    unsafe {
        let b = libb.get::<fn() -> i32>("b").expect("symbol 'b' not found");
        let result = b();
        println!("Result of b(): {}", result);
    }

    println!("Relocation with custom handler completed.");

    Ok(())
}
