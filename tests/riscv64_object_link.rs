use elf_loader::{Loader, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    env_logger::init();

    // 调试：打印当前工作目录
    let cwd = std::env::current_dir().expect("Failed to get current directory");
    eprintln!("Current working directory: {:?}", cwd);

    // 尝试不同的基础路径
    let base_dir = if let Ok(dir) = std::env::var("ELF_TEST_DIR") {
        PathBuf::from(dir)
    } else if cwd.join("target/riscv64-test").exists() {
        cwd.clone()
    } else {
        // 尝试查找项目根目录
        let mut current = cwd.clone();
        loop {
            if current.join("target/riscv64-test").exists() {
                break current;
            }
            if !current.pop() {
                // 找不到，使用当前目录
                break cwd.clone();
            }
        }
    };

    let b_path = base_dir.join("target/riscv64-test/b.o");
    let a_path = base_dir.join("target/riscv64-test/a.o");

    eprintln!("Loading b.o from: {:?}", b_path);
    eprintln!("Loading a.o from: {:?}", a_path);

    let mut loader = Loader::new();

    let b = loader
        .load_object(b_path.to_str().unwrap())?
        .relocator()
        .relocate()?;

    let a = loader
        .load_object(a_path.to_str().unwrap())?
        .relocator()
        .scope([&b])
        .relocate()?;

    let a_fn = unsafe { a.get::<extern "C" fn() -> i32>("a").unwrap() };
    let b_fn = unsafe { b.get::<extern "C" fn() -> i32>("b").unwrap() };

    let a_val = a_fn();
    let b_val = b_fn();

    println!("a() = {a_val}, b() = {b_val}");
    assert_eq!(b_val, 41);
    assert_eq!(a_val, 83);

    Ok(())
}
