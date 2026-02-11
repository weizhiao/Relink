// 主测试文件，调用所有测试

extern int call_test(int x);
extern int external_func(int x);
extern int* get_global_ptr(void);
extern int read_globals(void);
extern int modify_through_pointer(int delta);
extern int condition_test(int x);
extern int loop_test(int n);
extern int switch_test(int x);
extern int test_hi20_load(int index);
extern void test_hi20_store(int index, int value);
extern int test_extern_array(int index);
extern int call_through_table(int index, int value);
extern int sum_through_ptrs(void);
extern unsigned int get_func_offset(void);

int run_all_tests(void) {
    int passed = 0;
    int total = 0;

    // Test 1: Function calls
    total++;
    if (call_test(5) == 210) { // (5 + 100) * 2
        passed++;
    }

    // Test 2: Global variable access
    total++;
    if (read_globals() == 141) { // 42 + 99
        passed++;
    }

    // Test 3: Pointer manipulation
    total++;
    int* ptr = get_global_ptr();
    if (ptr != 0 && modify_through_pointer(8) == 50) { // 42 + 8
        passed++;
    }

    // Test 4: Conditional branches
    total++;
    if (condition_test(15) == 30 && condition_test(-5) == 5 && condition_test(5) == 6) {
        passed++;
    }

    // Test 5: Loops
    total++;
    if (loop_test(10) == 45) { // 0+1+2+...+9
        passed++;
    }

    // Test 6: Switch statements
    total++;
    if (switch_test(3) == 30 && switch_test(10) == 0) {
        passed++;
    }

    // Test 7: HI20/LO12 array access
    total++;
    test_hi20_store(50, 123);
    if (test_hi20_load(50) == 123) {
        passed++;
    }

    // Test 8: External array
    total++;
    if (test_extern_array(0) == 0) {
        passed++;
    }

    // Test 9: Function pointers
    total++;
    if (call_through_table(0, 10) == 11 && 
        call_through_table(1, 10) == 20 &&
        call_through_table(2, 10) == 9) {
        passed++;
    }

    // Test 10: Data pointers
    total++;
    if (sum_through_ptrs() == 60) { // 10 + 20 + 30
        passed++;
    }

    // Test 11: 32-bit operations
    total++;
    if (get_func_offset() != 0) {
        passed++;
    }

    return (passed << 16) | total; // Return passed in high 16 bits, total in low 16 bits
}
