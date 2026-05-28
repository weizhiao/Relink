// 测试指针和地址重定位 (R_RISCV_64)

typedef int (*func_ptr_t)(int);

int func_a(int x) { return x + 1; }
int func_b(int x) { return x * 2; }
int func_c(int x) { return x - 1; }

// 函数指针数组 - 产生 R_RISCV_64 重定位
func_ptr_t function_table[] = {
    func_a,
    func_b,
    func_c,
    0
};

int call_through_table(int index, int value) {
    if (index >= 0 && index < 3) {
        return function_table[index](value);
    }
    return 0;
}

// 数据指针
extern int data_x, data_y, data_z;
int* data_ptrs[] = {
    &data_x,
    &data_y,
    &data_z,
    0
};

int sum_through_ptrs(void) {
    int sum = 0;
    for (int i = 0; i < 3; i++) {
        sum += *data_ptrs[i];
    }
    return sum;
}

int data_x = 10;
int data_y = 20;
int data_z = 30;
