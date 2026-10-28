#ifndef SYDO_MEMORY_ALLOC_H
#define SYDO_MEMORY_ALLOC_H

#include <stddef.h>

typedef struct {
    size_t requested_peak, usable_peak, requested_live, usable_live;
    unsigned overflow;
} sydo_memory_usage;

void memory_start(void);
sydo_memory_usage memory_stop(void);

#endif
