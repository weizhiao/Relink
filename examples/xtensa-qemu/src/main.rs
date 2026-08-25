#![no_std]
#![no_main]

use core::{
    ffi::{CStr, c_char},
    ptr::addr_of_mut,
};

use elf_loader::{
    Loader, Relocator,
    image::{SyntheticModule, SyntheticSymbol},
    input::ElfBinary,
    memory::VmAddr,
    os::FixedMmap,
};
use esp_backtrace as _;
use esp_println::println;

const FIXTURE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fixture.so"));
const CAPACITY: usize = 8 * 1024;
const EXEC_ALIAS_OFFSET: usize = 0x14_0000;

#[repr(C, align(4096))]
struct ImageMemory([u8; CAPACITY]);

#[esp_hal::ram(unstable(rtc_fast))]
static mut IMAGE_MEMORY: ImageMemory = ImageMemory([0; CAPACITY]);

fn plugin_memory() -> FixedMmap {
    let host = VmAddr::from_ptr(addr_of_mut!(IMAGE_MEMORY));
    let addr = VmAddr::new(host.get() + EXEC_ALIAS_OFFSET);

    // RTC Fast Memory has separate writable and executable aliases.
    unsafe { FixedMmap::new(addr, host, CAPACITY) }
}

unsafe extern "C" fn print(message: *const c_char) {
    println!("{}", unsafe { CStr::from_ptr(message) }.to_str().unwrap());
}

#[esp_hal::main]
fn main() -> ! {
    let _peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(size: 128 * 1024);

    let host = SyntheticModule::new(
        "__host",
        [SyntheticSymbol::function("print", print as *const ())],
    );
    let plugin = Loader::new()
        .with_mmap(plugin_memory())
        .load_dylib(ElfBinary::new("fixture.so", FIXTURE))
        .and_then(|raw| Relocator::new().run(raw).modules([host]).relocate());

    match plugin {
        Ok(plugin) => {
            let hello = unsafe {
                plugin
                    .get::<unsafe extern "C" fn()>("hello")
                    .expect("missing hello")
            };
            let fibonacci = unsafe {
                plugin
                    .get::<unsafe extern "C" fn(u32) -> u32>("fibonacci")
                    .expect("missing fibonacci")
            };

            unsafe { hello() };
            println!("fibonacci(10) = {}", unsafe { fibonacci(10) });
        }
        Err(error) => println!("load failed: {error}"),
    }

    esp_hal::system::software_reset()
}
