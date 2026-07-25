extern void print(const char *message);

void hello(void) {
    print("Hello, World!");
}

unsigned fibonacci(unsigned n) {
    unsigned a = 0;
    unsigned b = 1;

    while (n-- != 0) {
        unsigned next = a + b;
        a = b;
        b = next;
    }
    return a;
}
