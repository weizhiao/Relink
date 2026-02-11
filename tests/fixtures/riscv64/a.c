extern int b_value;
extern int b(void);

int a(void) {
    return b() + b_value + 1;
}
