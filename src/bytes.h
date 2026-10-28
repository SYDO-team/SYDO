#ifndef SYDO_BYTES_H
#define SYDO_BYTES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint32_t sydo_load32(const uint8_t p[4]) {
    uint32_t x = 0;
    for (unsigned j = 0; j < 4; ++j) x |= (uint32_t)p[j] << (8 * j);
    return x;
}

static inline void sydo_store32(uint8_t p[4], uint32_t x) {
    for (unsigned j = 0; j < 4; ++j) p[j] = (uint8_t)(x >> (8 * j));
}

static inline unsigned sydo_bit(const uint8_t *p, size_t i) {
    return (p[i / 8] >> (i % 8)) & 1u;
}

static inline uint64_t sydo_transpose8(uint64_t x) {
    uint64_t t = (x ^ (x >> 7)) & UINT64_C(0x00aa00aa00aa00aa);
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & UINT64_C(0x0000cccc0000cccc);
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & UINT64_C(0x00000000f0f0f0f0);
    return x ^ t ^ (t << 28);
}

static inline uint32_t sydo_equal32(uint32_t x, uint32_t y) {
    uint32_t d = x ^ y;
    return ((d | (0u - d)) >> 31) - 1u;
}

static inline void sydo_xor(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; ++i) dst[i] ^= src[i];
}

static inline void sydo_wipe(void *memory, size_t n) {
    if (n >= 32) {
        /* The volatile call prevents elimination of the clearing operation. */
        static void *(* volatile clear_memory)(void *, int, size_t) = memset;
        clear_memory(memory, 0, n);
    } else {
        volatile uint8_t *p = (volatile uint8_t *)memory;
        while (n--) *p++ = 0;
    }
}

static inline unsigned sydo_difference(const uint8_t *a, const uint8_t *b, size_t n) {
    unsigned d = 0;
    for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
    return d;
}

#endif
