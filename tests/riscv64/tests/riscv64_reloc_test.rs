use elf_loader::{Loader, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let base_dir = if let Ok(dir) = std::env::var("ELF_TEST_DIR") {
        PathBuf::from(dir)
    } else {
        let cwd = std::env::current_dir().expect("Failed to get current directory");
        if cwd.join("target/riscv64-test").exists() {
            cwd
        } else {
            let mut current = cwd.clone();
            loop {
                if current.join("target/riscv64-test").exists() {
                    break current;
                }
                if !current.pop() {
                    break cwd;
                }
            }
        }
    };

    println!("Testing comprehensive RISC-V 64 relocations...\n");

    let test_dir = base_dir.join("target/riscv64-test");
    let mut loader = Loader::new();

    // 加载所有测试模块
    let test_calls = loader
        .load_object(test_dir.join("test_call.o").to_str().unwrap())?
        .relocator()
        .relocate()?;

    let test_globals = loader
        .load_object(test_dir.join("test_globals.o").to_str().unwrap())?
        .relocator()
        .scope([&test_calls])
        .relocate()?;

    let test_branches = loader
        .load_object(test_dir.join("test_branches.o").to_str().unwrap())?
        .relocator()
        .scope([&test_calls, &test_globals])
        .relocate()?;

    let test_hi_lo = loader
        .load_object(test_dir.join("test_hi_lo.o").to_str().unwrap())?
        .relocator()
        .scope([&test_calls, &test_globals, &test_branches])
        .relocate()?;

    let test_pointers = loader
        .load_object(test_dir.join("test_pointers.o").to_str().unwrap())?
        .relocator()
        .scope([&test_calls, &test_globals, &test_branches, &test_hi_lo])
        .relocate()?;

    let test_32bit = loader
        .load_object(test_dir.join("test_32bit.o").to_str().unwrap())?
        .relocator()
        .scope([
            &test_calls,
            &test_globals,
            &test_branches,
            &test_hi_lo,
            &test_pointers,
        ])
        .relocate()?;

    let test_main = loader
        .load_object(test_dir.join("test_main.o").to_str().unwrap())?
        .relocator()
        .scope([
            &test_calls,
            &test_globals,
            &test_branches,
            &test_hi_lo,
            &test_pointers,
            &test_32bit,
        ])
        .relocate()?;

    println!("All modules loaded and relocated successfully!\n");

    // 验证特定功能 (在 run_all_tests 之前，保持初始状态)
    println!("Initial verification:");

    let call_test = unsafe {
        test_calls
            .get::<extern "C" fn(i32) -> i32>("call_test")
            .unwrap()
    };
    let result = call_test(5);
    println!("  call_test(5) = {} (expected: 210)", result);
    assert_eq!(result, 210);

    let read_globals = unsafe {
        test_globals
            .get::<extern "C" fn() -> i32>("read_globals")
            .unwrap()
    };
    let result = read_globals();
    println!("  read_globals() = {} (expected: 141)", result);
    assert_eq!(result, 141);

    let condition_test = unsafe {
        test_branches
            .get::<extern "C" fn(i32) -> i32>("condition_test")
            .unwrap()
    };
    println!(
        "  condition_test(15) = {} (expected: 30)",
        condition_test(15)
    );
    println!(
        "  condition_test(-5) = {} (expected: 5)",
        condition_test(-5)
    );
    println!("  condition_test(5) = {} (expected: 6)", condition_test(5));
    assert_eq!(condition_test(15), 30);
    assert_eq!(condition_test(-5), 5);
    assert_eq!(condition_test(5), 6);

    let loop_test = unsafe {
        test_branches
            .get::<extern "C" fn(i32) -> i32>("loop_test")
            .unwrap()
    };
    let result = loop_test(10);
    println!("  loop_test(10) = {} (expected: 45)", result);
    assert_eq!(result, 45);

    let switch_test = unsafe {
        test_branches
            .get::<extern "C" fn(i32) -> i32>("switch_test")
            .unwrap()
    };
    println!("  switch_test(3) = {} (expected: 30)", switch_test(3));
    println!("  switch_test(10) = {} (expected: 0)", switch_test(10));
    assert_eq!(switch_test(3), 30);
    assert_eq!(switch_test(10), 0);

    let call_through_table = unsafe {
        test_pointers
            .get::<extern "C" fn(i32, i32) -> i32>("call_through_table")
            .unwrap()
    };
    println!(
        "  call_through_table(0, 10) = {} (expected: 11)",
        call_through_table(0, 10)
    );
    println!(
        "  call_through_table(1, 10) = {} (expected: 20)",
        call_through_table(1, 10)
    );
    println!(
        "  call_through_table(2, 10) = {} (expected: 9)",
        call_through_table(2, 10)
    );
    assert_eq!(call_through_table(0, 10), 11);
    assert_eq!(call_through_table(1, 10), 20);
    assert_eq!(call_through_table(2, 10), 9);

    println!("\n========================================");

    // 运行测试
    let run_all_tests = unsafe {
        test_main
            .get::<extern "C" fn() -> i32>("run_all_tests")
            .expect("Failed to find run_all_tests function")
    };

    let result = run_all_tests();
    let passed = (result >> 16) as u16;
    let total = (result & 0xFFFF) as u16;

    println!("Comprehensive Test Results: {}/{} passed", passed, total);

    if passed == total {
        println!("✓ All comprehensive tests passed!");
    } else {
        println!("✗ {} tests failed", total - passed);
        std::process::exit(1);
    }

    println!("\n✓ All RISC-V 64 relocation tests completed successfully!");

    Ok(())
}
