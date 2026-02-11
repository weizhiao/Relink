// 测试 HI20/LO12 寻址模式 (R_RISCV_HI20, R_RISCV_LO12_I, R_RISCV_LO12_S)

// 使用大数组来强制使用 HI20/LO12 寻址
static int large_array[1000];
extern int extern_array[100];

int test_hi20_load(int index) {
    // 测试 R_RISCV_HI20 + R_RISCV_LO12_I (load)
    if (index >= 0 && index < 1000) {
        return large_array[index];
    }
    return 0;
}

void test_hi20_store(int index, int value) {
    // 测试 R_RISCV_HI20 + R_RISCV_LO12_S (store)
    if (index >= 0 && index < 1000) {
        large_array[index] = value;
    }
}

int test_extern_array(int index) {
    if (index >= 0 && index < 100) {
        return extern_array[index];
    }
    return -1;
}

int extern_array[100] = {0};
