#![no_std]
#![no_main]

use core::{
    ffi::CStr,
    panic::PanicInfo,
    ptr::{addr_of_mut, null},
};
use elf_loader::{
    Loader, Result,
    arch::REL_RELATIVE,
    elf::{ElfDyn, ElfDynamicTag, ElfPhdr, ElfProgramType, ElfRela},
    image::RawElf,
    input::ElfFile,
};
use linked_list_allocator::LockedHeap;
use mini_loader::{exit, fatal, print_str};

#[inline(always)]
fn expect_some<T>(value: Option<T>, message: &'static str) -> T {
    match value {
        Some(value) => value,
        None => fatal(message),
    }
}

#[inline(always)]
fn expect_ok<T, E>(value: core::result::Result<T, E>, message: &'static str) -> T {
    match value {
        Ok(value) => value,
        Err(_) => fatal(message),
    }
}

#[inline(always)]
fn print_decimal(mut value: usize) {
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();

    if value == 0 {
        index -= 1;
        buffer[index] = b'0';
    } else {
        while value != 0 {
            index -= 1;
            buffer[index] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }

    let digits = unsafe { core::str::from_utf8_unchecked(&buffer[index..]) };
    print_str(digits);
}

#[inline(always)]
fn load_elf(name: &str) -> Result<RawElf<()>> {
    let mut loader = Loader::new();
    let object = ElfFile::from_path(name)?;
    loader.load(object)
}

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_EXECFN: u64 = 31;

#[global_allocator]
static mut ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_SIZE: usize = 1024 * 1024; // 1MB heap
static mut HEAP_BUF: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        print_str(location.file());
        print_str(":");
        print_decimal(location.line() as usize);
        print_str(":");
        print_decimal(location.column() as usize);
        print_str(" panic\n");
    } else {
        print_str("panic\n");
    }
    exit(-1);
}

#[repr(C)]
struct Aux {
    tag: u64,
    val: u64,
}

// auxv <---sp + argc + 2 + env_count + 2
// 0    <---sp + argc + 2 + env_count + 1
// env  <---sp + argc + 2
// 0    <---sp + argc + 1
// argv <---sp + 1
// argc <---sp
#[unsafe(no_mangle)]
unsafe extern "C" fn rust_main(sp: *mut usize, dynv: *mut ElfDyn) {
    let mut cur_dyn_ptr = dynv;
    let mut cur_dyn = unsafe { &*dynv };
    let mut rela = None;
    let mut rela_count = None;
    loop {
        match cur_dyn.tag() {
            ElfDynamicTag::NULL => break,
            ElfDynamicTag::RELA => rela = Some(cur_dyn.value()),
            ElfDynamicTag::RELACOUNT => rela_count = Some(cur_dyn.value()),
            _ => {}
        }
        cur_dyn_ptr = unsafe { cur_dyn_ptr.add(1) };
        cur_dyn = unsafe { &mut *cur_dyn_ptr };
    }
    let rela = expect_some(rela, "missing DT_RELA\n");
    let rela_count = expect_some(rela_count, "missing DT_RELACOUNT\n");

    let mut base = 0;
    let mut phnum = 0;
    let mut ph = null();

    let argc = unsafe { sp.read() };
    let env = unsafe { sp.add(argc + 1 + 1) };
    let mut env_count = 0;
    let mut cur_env = env;
    while unsafe { cur_env.read() } != 0 {
        env_count += 1;
        cur_env = unsafe { cur_env.add(1) };
    }
    let auxv = unsafe { env.add(env_count + 1).cast::<Aux>() };

    // 获得mini-loader的phdrs
    let mut cur_aux_ptr = auxv;
    let mut cur_aux = unsafe { cur_aux_ptr.read() };
    loop {
        match cur_aux.tag {
            AT_NULL => break,
            AT_PHDR => ph = cur_aux.val as *const ElfPhdr,
            AT_PHNUM => phnum = cur_aux.val,
            AT_BASE => base = cur_aux.val as usize,
            _ => {}
        }
        cur_aux_ptr = unsafe { cur_aux_ptr.add(1) };
        cur_aux = unsafe { cur_aux_ptr.read() };
    }
    // 通常是0，需要自行计算
    if base == 0 {
        let phdrs = unsafe { &*core::ptr::slice_from_raw_parts(ph, phnum as usize) };
        for phdr in phdrs {
            if phdr.program_type() == ElfProgramType::DYNAMIC {
                base = dynv as usize - phdr.p_vaddr();
                break;
            }
        }
    }
    // 自举，mini-loader自己对自己重定位
    let rela_ptr = (rela as usize + base) as *const ElfRela;
    let relas = unsafe { &*core::ptr::slice_from_raw_parts(rela_ptr, rela_count as usize) };
    for rela in relas {
        if rela.r_type() != REL_RELATIVE as usize {
            print_str("unknown rela type");
        }
        let ptr = (rela.r_offset() + base) as *mut usize;
        unsafe { ptr.write(base.wrapping_add_signed(rela.r_addend(base))) };
    }
    // 至此就完成自举，可以进行函数调用了
    unsafe {
        ALLOCATOR = LockedHeap::new(addr_of_mut!(HEAP_BUF).cast(), HEAP_SIZE);
    }

    if argc == 1 {
        fatal("no input file\n");
    }
    // 加载输入的elf文件
    let argv = unsafe { sp.add(1) };
    let elf_name_raw = unsafe { argv.add(1).read() as *const i8 };
    let elf_name = unsafe { CStr::from_ptr(elf_name_raw as _) };

    let elf_name = expect_ok(elf_name.to_str(), "input path is not valid UTF-8\n");
    let elf = expect_ok(load_elf(elf_name), "failed to load input ELF\n");
    let mut interp_dylib = None;
    // 加载动态加载器ld.so，如果有的话
    if let Some(interp_name) = elf.interp() {
        interp_dylib = Some(expect_ok(
            load_elf(interp_name),
            "failed to load interpreter\n",
        ));
    }
    let phdrs = elf.phdrs().unwrap_or(&[]);
    // 重新设置aux
    let mut cur_aux_ptr = auxv;
    let mut cur_aux = unsafe { &mut *cur_aux_ptr };
    loop {
        match cur_aux.tag {
            AT_NULL => break,
            AT_PHDR => cur_aux.val = phdrs.as_ptr() as u64,
            AT_PHNUM => cur_aux.val = phdrs.len() as u64,
            AT_PHENT => cur_aux.val = size_of::<ElfPhdr>() as u64,
            AT_ENTRY => cur_aux.val = elf.entry() as u64,
            AT_EXECFN => cur_aux.val = unsafe { argv.add(1).read() } as u64,
            AT_BASE => cur_aux.val = interp_dylib.as_ref().map(|e| e.base()).unwrap_or(0) as u64,
            _ => {}
        }
        cur_aux_ptr = unsafe { cur_aux_ptr.add(1) };
        cur_aux = unsafe { &mut *cur_aux_ptr };
    }

    unsafe extern "C" {
        fn trampoline(entry: usize, sp: *const usize) -> !;
    }

    // 修改argv，将mini-loader去除，这里涉及到16字节对齐，因此只能拷贝
    let size = unsafe { cur_aux_ptr.add(1) as usize - sp.add(1) as usize };
    unsafe { core::ptr::copy(sp.add(1), sp, size / size_of::<usize>()) };
    unsafe { sp.write(argc - 1) };

    unsafe {
        if let Some(interp_dylib) = interp_dylib {
            trampoline(interp_dylib.entry(), sp);
        } else {
            trampoline(elf.entry(), sp);
        }
    }
}
