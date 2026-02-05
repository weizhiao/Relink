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
    elf::{
        ElfDyn as Dyn, ElfPhdr,
        abi::{DT_NULL, DT_RELA, DT_RELACOUNT, PT_DYNAMIC},
    },
    image::RawElf,
    input::ElfFile,
};
use itoa::Buffer;
use linked_list_allocator::LockedHeap;
use mini_loader::{exit, print_str, println};

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
static mut HEAP_INIT: bool = false;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let location = info.location().unwrap();
    let mut buf = Buffer::new();
    print_str(location.file());
    print_str(":");
    print_str(buf.format(location.line()));
    print_str(":");
    print_str(buf.format(location.column()));
    print_str(" ");
    if let Some(msg) = info.message().as_str() {
        print_str(msg);
        print_str("\n");
    } else {
        if unsafe { HEAP_INIT } {
            println!("{}", info.message())
        }
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
unsafe extern "C" fn rust_main(sp: *mut usize, dynv: *mut Dyn) {
    let mut cur_dyn_ptr = dynv;
    let mut cur_dyn = unsafe { &*dynv };
    let mut rela = None;
    let mut rela_count = None;
    loop {
        match cur_dyn.d_tag {
            DT_NULL => break,
            DT_RELA => rela = Some(cur_dyn.d_un),
            DT_RELACOUNT => rela_count = Some(cur_dyn.d_un),
            _ => {}
        }
        cur_dyn_ptr = unsafe { cur_dyn_ptr.add(1) };
        cur_dyn = unsafe { &mut *cur_dyn_ptr };
    }
    let rela = rela.unwrap();
    let rela_count = rela_count.unwrap();

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
            AT_PHDR => ph = cur_aux.val as *const elf::segment::Elf64_Phdr,
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
        let mut idx = 0;
        loop {
            let phdr = &phdrs[idx];
            if phdr.p_type == PT_DYNAMIC {
                base = dynv as usize - phdr.p_vaddr as usize;
                break;
            }
            idx += 1;
        }
    }
    // 自举，mini-loader自己对自己重定位
    let rela_ptr = (rela as usize + base) as *const elf::relocation::Elf64_Rela;
    let relas = unsafe { &*core::ptr::slice_from_raw_parts(rela_ptr, rela_count as usize) };
    for rela in relas {
        if rela.r_info as usize & 0xFFFFFFFF != REL_RELATIVE as usize {
            print_str("unknown rela type");
        }
        let ptr = (rela.r_offset as usize + base) as *mut usize;
        unsafe { ptr.write(base + rela.r_addend as usize) };
    }
    // 至此就完成自举，可以进行函数调用了
    unsafe {
        ALLOCATOR = LockedHeap::new(addr_of_mut!(HEAP_BUF).cast(), HEAP_SIZE);
        HEAP_INIT = true;
    }

    if argc == 1 {
        panic!("no input file");
    }
    // 加载输入的elf文件
    let argv = unsafe { sp.add(1) };
    let elf_name_raw = unsafe { argv.add(1).read() as *const i8 };
    let elf_name = unsafe { CStr::from_ptr(elf_name_raw as _) };

    let elf = load_elf(elf_name.to_str().unwrap()).unwrap();
    let mut interp_dylib = None;
    // 加载动态加载器ld.so，如果有的话
    if let Some(interp_name) = elf.interp() {
        interp_dylib = Some(load_elf(interp_name).expect("Failed to load interpreter"));
    }
    let phdrs = elf.phdrs().unwrap_or_default();
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
