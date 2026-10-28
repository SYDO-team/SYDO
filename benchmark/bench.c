#define _POSIX_C_SOURCE 200809L
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "parameters.h"
#include "profile.h"
#include <sys/resource.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <x86intrin.h>
#endif

DRNG_ctx drng_algorithm;

static int cycles_available(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned a, b, c, d;
    return __get_cpuid(0x80000001u, &a, &b, &c, &d) && (d & (1u << 27));
#else
    return 0;
#endif
}

static uint64_t cycles_start(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned a, b, c, d;
    __cpuid(0, a, b, c, d);
    atomic_signal_fence(memory_order_seq_cst);
    uint64_t value = __rdtsc();
    atomic_signal_fence(memory_order_seq_cst);
    return value;
#else
    return 0;
#endif
}

static uint64_t cycles_stop(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned a, b, c, d, auxiliary;
    atomic_signal_fence(memory_order_seq_cst);
    uint64_t value = __rdtscp(&auxiliary);
    __cpuid(0, a, b, c, d);
    atomic_signal_fence(memory_order_seq_cst);
    return value;
#else
    return 0;
#endif
}

static uint64_t nanoseconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { perror("clock_gettime"); exit(2); }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int order_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static unsigned long count_argument(const char *text) {
    char *end;
    errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !*text || *end || !n || n > 1000000) { fprintf(stderr, "invalid positive count: %s\n", text); exit(2); }
    return n;
}

int main(int argc, char **argv) {
    int has_cycles = cycles_available();
    if (argc == 2 && !strcmp(argv[1], "--cycle-source")) {
        puts(has_cycles ? "x86 TSC" : "unavailable");
        return 0;
    }
    if (argc != 4) { fprintf(stderr, "usage: %s keygen|sign|verify ROUNDS WARMUP\n", argv[0]); return 2; }
    const char *operation = argv[1];
    unsigned long rounds = count_argument(argv[2]), warmup = count_argument(argv[3]);
    if (strcmp(operation, "keygen") && strcmp(operation, "sign") && strcmp(operation, "verify")) return 2;
    uint8_t seed[64], pk[SYDO_PK_BYTES], sk[SYDO_SK_BYTES], signature[SYDO_SIG_BYTES];
    uint8_t message[] = "SYndrome DecOding (SYDO) signature scheme";
    unsigned long long pk_bytes = SYDO_PK_BYTES, sk_bytes = SYDO_SK_BYTES, sig_bytes = SYDO_SIG_BYTES;
    for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)(0xa5u ^ i);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) || sig_keygen(pk, &pk_bytes, sk, &sk_bytes)) return 1;
    if (!strcmp(operation, "verify") && sig_sign(sk, sk_bytes, message, sizeof(message) - 1, signature, &sig_bytes)) return 1;
    uint64_t *times = malloc(2u * rounds * sizeof(*times));
    if (!times) return 2;
    uint64_t *cycles = times + rounds;
    double total = 0, total_cycles = 0;
    for (unsigned long i = 0; i < warmup + rounds; ++i) {
#ifdef SYDO_PROFILE
        if (i == warmup) profile_reset();
#endif
        uint64_t cycle_begin = has_cycles ? cycles_start() : 0;
        uint64_t start = nanoseconds();
        int status;
        if (!strcmp(operation, "keygen")) status = sig_keygen(pk, &pk_bytes, sk, &sk_bytes);
        else if (!strcmp(operation, "sign")) status = sig_sign(sk, sk_bytes, message, sizeof(message) - 1, signature, &sig_bytes);
        else status = sig_verify(pk, pk_bytes, signature, sig_bytes, message, sizeof(message) - 1);
        uint64_t elapsed = nanoseconds() - start;
        uint64_t elapsed_cycles = has_cycles ? cycles_stop() - cycle_begin : 0;
        if (status) { fprintf(stderr, "%s failed at iteration %lu with code %d\n", operation, i, status); free(times); return 1; }
        if (i >= warmup) {
            times[i - warmup] = elapsed;
            cycles[i - warmup] = elapsed_cycles;
            total += (double)elapsed;
            total_cycles += (double)elapsed_cycles;
        }
    }
    const char *samples_path = getenv("SYDO_BENCH_SAMPLES_OUT");
    if (samples_path) {
        FILE *samples = fopen(samples_path, "w");
        if (!samples) { free(times); return 2; }
        fprintf(samples, "sample,elapsed_ns,cycles\n");
        for (unsigned long i = 0; i < rounds; ++i) {
            fprintf(samples, "%lu,%llu,", i, (unsigned long long)times[i]);
            if (has_cycles) fprintf(samples, "%llu\n", (unsigned long long)cycles[i]);
            else fprintf(samples, "NA\n");
        }
        int failed = ferror(samples);
        if (fclose(samples)) failed = 1;
        if (failed) { free(times); return 2; }
    }
#ifdef SYDO_PROFILE
    const char *profile_path = getenv("SYDO_PROFILE_OUT");
    if (!profile_path) { free(times); return 2; }
    FILE *profile_output = fopen(profile_path, "w");
    if (!profile_output) { free(times); return 2; }
    int profile_status = profile_write(profile_output);
    if (fclose(profile_output) || profile_status) { free(times); return 2; }
#endif
    if (!strcmp(operation, "sign") && sig_verify(pk, pk_bytes, signature, sig_bytes, message, sizeof(message) - 1)) return 1;
    qsort(times, rounds, sizeof(*times), order_u64);
    double median = rounds % 2 ? (double)times[rounds / 2] : ((double)times[rounds / 2 - 1] + (double)times[rounds / 2]) / 2;
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) { free(times); return 2; }
#ifdef SYDO_AVX2
    const char *implementation = "avx2";
#else
    const char *implementation = "ref";
#endif
    printf("%s,%s,%s,%lu,%.3f,%.3f,%.3f,%.3f,%ld,%lu,", SYDO_INSTANCE, implementation, operation, rounds,
           total / (1000.0 * rounds), median / 1000.0, times[0] / 1000.0, times[rounds - 1] / 1000.0, usage.ru_maxrss, warmup);
    if (has_cycles) printf("%.3f,%.6f,x86 TSC\n", total_cycles / rounds, total_cycles / (1000000.0 * rounds));
    else printf("NA,NA,unavailable\n");
    free(times);
    return 0;
}
