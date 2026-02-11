// 测试分支和跳转重定位 (R_RISCV_BRANCH, R_RISCV_JAL)

int condition_test(int x) {
    // 测试条件分支 (R_RISCV_BRANCH)
    if (x > 10) {
        return x * 2;
    } else if (x < 0) {
        return -x;
    } else {
        return x + 1;
    }
}

int loop_test(int n) {
    // 测试循环中的分支
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

int switch_test(int x) {
    // 测试跳转表 (可能产生 R_RISCV_JAL)
    switch (x) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        case 4: return 40;
        case 5: return 50;
        default: return 0;
    }
}
