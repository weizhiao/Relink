extern unsigned char copy_a[4];
extern unsigned char copy_b[5];

void _start(void) {}

unsigned int copy_sum(void) {
    return copy_a[0] + copy_b[0];
}
