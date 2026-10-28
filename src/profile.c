#define _POSIX_C_SOURCE 200809L
#include "profile.h"

#ifdef SYDO_PROFILE
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

typedef struct { uint64_t calls, inclusive, exclusive; } measurement;
typedef struct { enum sydo_profile_stage stage; uint64_t start, children; } frame;
static measurement totals[PROFILE_STAGE_COUNT];
static frame stack[32];
static unsigned depth;

static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) abort();
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

void profile_begin(enum sydo_profile_stage stage) {
    if (depth == 32) abort();
    stack[depth++] = (frame){stage, now(), 0};
}

void profile_end(enum sydo_profile_stage stage) {
    uint64_t stop = now();
    if (!depth || stack[depth - 1].stage != stage) abort();
    frame current = stack[--depth];
    uint64_t elapsed = stop - current.start;
    ++totals[stage].calls;
    totals[stage].inclusive += elapsed;
    totals[stage].exclusive += elapsed - current.children;
    if (depth) stack[depth - 1].children += elapsed;
}

void profile_reset(void) {
    if (depth) abort();
    memset(totals, 0, sizeof(totals));
}

int profile_write(FILE *output) {
    static const char *const names[] = {
        "sign", "verify", "tree_expand", "leaf_commit", "commitment_hash",
        "vole_generate", "vole_check", "matrix_expand", "matrix_fold",
        "constraints_generate", "constraints_verify", "grinding", "opening",
        "bavc_reconstruct", "xof"
    };
    if (depth) return -1;
    if (fprintf(output, "stage,calls,inclusive_ns,exclusive_ns\n") < 0) return -1;
    for (unsigned i = 0; i < PROFILE_STAGE_COUNT; ++i)
        if (totals[i].calls && fprintf(output, "%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
            names[i], totals[i].calls, totals[i].inclusive, totals[i].exclusive) < 0) return -1;
    return ferror(output) ? -1 : 0;
}
#endif
