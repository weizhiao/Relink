// 测试全局变量和指针重定位 (R_RISCV_64, R_RISCV_PCREL_HI20/LO12, R_RISCV_GOT_HI20)

int global_var = 42;
int another_var = 99;
const char* global_string = "Hello RISC-V";

int* get_global_ptr(void) {
    return &global_var;
}

int read_globals(void) {
    // 测试 PC-relative 访问
    int local = global_var;
    local += another_var;
    return local;
}

int modify_through_pointer(int delta) {
    int* ptr = &global_var;
    *ptr += delta;
    return *ptr;
}
