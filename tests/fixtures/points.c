__attribute__((section(".points"))) static volatile int base_points = 40;

int points(void) {
    return base_points;
}
