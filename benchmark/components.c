#define _POSIX_C_SOURCE 200809L
#include "component_api.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(2);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static unsigned count(const char *value) {
    char *end;
    errno = 0;
    unsigned long result = strtoul(value, &end, 10);
    if (errno || !*value || *end || !result || result > 1000000) exit(2);
    return (unsigned)result;
}

static int compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        #ifdef SYDO_CIPHER_BLAKE2S
        puts("field_mul\nblake2s_expand\nblake2s_encrypt\ntree_prg");
        #else
        puts("field_mul\n" SYDO_MATRIX_EXPAND_NAME "\n" SYDO_MATRIX_ENCRYPT_NAME "\n"
             SYDO_CIPHER_EXPAND_NAME "\n" SYDO_CIPHER_ENCRYPT_NAME "\ntree_prg");
        #endif
        return 0;
    }
    if (argc != 4) { fprintf(stderr, "usage: %s COMPONENT ROUNDS WARMUP\n", argv[0]); return 2; }
    unsigned rounds = count(argv[2]), warmup = count(argv[3]);
    unsigned work = component_work_items(argv[1]);
    if (!work) return 2;
    void *context = component_setup(argv[1]);
    uint64_t *times = malloc(rounds * sizeof(*times)), checksum = 0;
    if (!context || !times) return 2;
    double sum = 0;
    for (unsigned i = 0; i < warmup + rounds; ++i) {
        uint64_t start = now();
        component_evaluate(context, argv[1]);
        uint64_t elapsed = now() - start;
        checksum ^= component_checksum(context, argv[1]);
        if (i >= warmup) { times[i - warmup] = elapsed; sum += (double)elapsed; }
    }
    qsort(times, rounds, sizeof(*times), compare);
    double median = rounds % 2 ? (double)times[rounds / 2] :
        ((double)times[rounds / 2 - 1] + (double)times[rounds / 2]) / 2;
    printf("%s,%u,%u,%.3f,%.3f,%.3f,%.3f,%016" PRIx64 "\n", argv[1], rounds, work,
        sum / rounds / work, median / work, (double)times[0] / work, (double)times[rounds - 1] / work, checksum);
    component_teardown(context);
    free(times);
    return 0;
}
