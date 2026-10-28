#define _POSIX_C_SOURCE 200112L
#include "memory_alloc.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    memory_start();
    uint8_t *p = malloc(31), *q = calloc(7, 13);
    if (!p || !q) return 2;
    ((volatile uint8_t *)p)[0] = 1; ((volatile uint8_t *)q)[90] = 2;
    sydo_memory_usage u = memory_stop();
    if (u.overflow || u.requested_peak != 122 || u.requested_live != 122 || u.usable_peak < 122) return 1;
    free(p); free(q);

    memory_start();
    p = malloc(31);
    if (!p) return 2;
    ((volatile uint8_t *)p)[30] = 3;
    p = realloc(p, 173);
    if (!p) return 2;
    ((volatile uint8_t *)p)[172] = 4;
    free(p);
    u = memory_stop();
    if (u.overflow || u.requested_peak != 173 || u.requested_live || u.usable_live) return 1;

    memory_start();
    void *aligned = NULL;
    if (posix_memalign(&aligned, 64, 155)) return 2;
    ((volatile uint8_t *)aligned)[154] = 5;
    free(aligned);
    u = memory_stop();
    if (u.overflow || u.requested_peak != 155 || u.requested_live || u.usable_live) return 1;
    puts("allocation tracking: malloc/calloc/realloc/alignment and releases verified");
    return 0;
}
