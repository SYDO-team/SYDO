#define _GNU_SOURCE
#include "memory_alloc.h"
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);
extern void *__libc_memalign(size_t, size_t);

typedef struct { void *pointer; size_t requested, usable; } allocation;
static allocation allocations[8192];
static sydo_memory_usage usage;
static unsigned active;

static void add(void *pointer, size_t size) {
    if (!active || !pointer) return;
    for (size_t i = 0; i < 8192; ++i)
        if (!allocations[i].pointer) {
            size_t usable = malloc_usable_size(pointer);
            allocations[i] = (allocation){pointer, size, usable};
            usage.requested_live += size; usage.usable_live += usable;
            if (usage.requested_peak < usage.requested_live) usage.requested_peak = usage.requested_live;
            if (usage.usable_peak < usage.usable_live) usage.usable_peak = usage.usable_live;
            return;
        }
    usage.overflow = 1;
}

static size_t find(void *pointer) {
    if (active && pointer)
        for (size_t i = 0; i < 8192; ++i) if (allocations[i].pointer == pointer) return i;
    return 8192;
}

static void remove_index(size_t i) {
    if (i == 8192) return;
    usage.requested_live -= allocations[i].requested;
    usage.usable_live -= allocations[i].usable;
    allocations[i] = (allocation){0};
}

void *malloc(size_t size) {
    void *p = __libc_malloc(size); add(p, size); return p;
}

void *calloc(size_t count, size_t size) {
    void *p = __libc_calloc(count, size);
    if (!size || count <= SIZE_MAX / size) add(p, count * size);
    return p;
}

void *realloc(void *pointer, size_t size) {
    size_t i = find(pointer);
    void *p = __libc_realloc(pointer, size);
    if (p || !size) { remove_index(i); add(p, size); }
    return p;
}

void free(void *pointer) {
    remove_index(find(pointer)); __libc_free(pointer);
}

void *aligned_alloc(size_t alignment, size_t size) {
    void *p = __libc_memalign(alignment, size); add(p, size); return p;
}

void *memalign(size_t alignment, size_t size) {
    void *p = __libc_memalign(alignment, size); add(p, size); return p;
}

int posix_memalign(void **pointer, size_t alignment, size_t size) {
    if (alignment < sizeof(void *) || (alignment & (alignment - 1))) return EINVAL;
    void *p = __libc_memalign(alignment, size);
    if (!p) return ENOMEM;
    *pointer = p; add(p, size); return 0;
}

void memory_start(void) {
    active = 0;
    memset(allocations, 0, sizeof(allocations));
    memset(&usage, 0, sizeof(usage));
    active = 1;
}

sydo_memory_usage memory_stop(void) {
    active = 0;
    return usage;
}
