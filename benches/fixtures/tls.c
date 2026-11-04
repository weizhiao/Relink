/* Keep the same general-dynamic TLS access sequence for both loaders. */
__thread unsigned long long relink_bench_tls_value = 7;

__attribute__((noinline)) unsigned long long tls_increment(void) {
    return ++relink_bench_tls_value;
}
