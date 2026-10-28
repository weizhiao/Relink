static int value;

int example_add(int a, int b) {
    return a + b;
}

int example_value(void) {
    return value;
}

// Calling an exported function also gives observer a symbol binding to report.
__attribute__((constructor)) static void initialize(void) {
    value = example_add(3, 4);
}

__attribute__((destructor)) static void finalize(void) {
    value = 0;
}
