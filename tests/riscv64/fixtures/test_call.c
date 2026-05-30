// 测试函数调用重定位 (R_RISCV_CALL, R_RISCV_CALL_PLT)

int external_func(int x);
static int internal_value = 100;

int call_test(int x) {
    // 测试外部函数调用
    return external_func(x + internal_value);
}

int external_func(int x) {
    return x * 2;
}
