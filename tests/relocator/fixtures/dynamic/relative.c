static int local_value = 23;
int *relative_pointer = &local_value;

int *local_address(void) {
    return &local_value;
}

int read_relative(void) {
    return *relative_pointer;
}
