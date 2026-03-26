#[path = "common/mod.rs"]
mod fixture_support;

use elf_loader::{
    Loader, Result,
    relocation::{HandleResult, RelocationContext, RelocationHandler},
};

struct MyRelocHandler;

fn my_print(s: &str) {
    println!("Caught by MyRelocHandler: {}", s);
}

impl RelocationHandler for MyRelocHandler {
    fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
        let r_sym = ctx.rel().r_symbol();
        let symtab = ctx.lib().symtab();
        let (_, sym_info) = symtab.symbol_idx(r_sym);

        if sym_info.name() == "print" {
            let target_addr = (ctx.lib().base() + ctx.rel().r_offset()) as *mut usize;
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
