/* Benchmark adapter; the pinned NPB numerical algorithm remains in cg.c. */
#include "npb-C.h"
#include <stdint.h>
#include <time.h>

struct cg_result {
    uint64_t kernel_ns;
    double zeta;
    int verified, dimension, iterations;
    char class;
};

double relink_cg_zeta;
static struct cg_result result;
static uint64_t started;

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

/* Suppress the original progress printing in all loader cases. */
int relink_cg_quiet_printf(const char *format, ...) { return 0; }

/* CG uses only timer 1 around its original inverse-power iteration loop. */
void timer_clear(int n) { result.kernel_ns = 0; }
void timer_start(int n) { started = monotonic_ns(); }
void timer_stop(int n) { result.kernel_ns += monotonic_ns() - started; }
double timer_read(int n) { return result.kernel_ns / 1e9; }

void c_print_results(char *name, char class, int n1, int n2, int n3,
                     int niter, int nthreads, double t, double mops,
                     char *optype, int verified, char *version, char *date,
                     char *cc, char *clink, char *c_lib, char *c_inc,
                     char *cflags, char *clinkflags, char *rand) {
    result.verified = verified;
    result.dimension = n1;
    result.iterations = niter;
    result.class = class;
}

extern int npb_main(int, char **);

void relink_cg_run(struct cg_result *out) {
    result = (struct cg_result){0};
    npb_main(0, NULL);
    result.zeta = relink_cg_zeta;
    *out = result;
}
