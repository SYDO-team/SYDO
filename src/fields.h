#ifndef SYDO_FIELDS_H
#define SYDO_FIELDS_H

#include "parameters.h"
#include <string.h>

#ifdef SYDO_AVX2
#include <immintrin.h>
typedef union {
    uint64_t word[(SYDO_FIELD_WORDS + 1u) & ~1u];
    __m128i vector[(SYDO_FIELD_WORDS + 1u) / 2u];
} sydo_field;
#else
typedef struct { uint64_t word[SYDO_FIELD_WORDS]; } sydo_field;
#endif

static inline sydo_field field_zero(void) {
    sydo_field x = {{0}};
    return x;
}

static inline sydo_field field_add(sydo_field a, sydo_field b) {
#ifdef SYDO_AVX2
    for (unsigned i = 0; i < (SYDO_FIELD_WORDS + 1u) / 2u; ++i)
        a.vector[i] = _mm_xor_si128(a.vector[i], b.vector[i]);
#else
    for (unsigned i = 0; i < SYDO_FIELD_WORDS; ++i) a.word[i] ^= b.word[i];
#endif
    return a;
}

static inline sydo_field field_mask(sydo_field a, unsigned bit) {
    uint64_t mask = UINT64_C(0) - (uint64_t)bit;
#ifdef SYDO_AVX2
    __m128i lanes = _mm_set1_epi64x((long long)mask);
    for (unsigned i = 0; i < (SYDO_FIELD_WORDS + 1u) / 2u; ++i)
        a.vector[i] = _mm_and_si128(a.vector[i], lanes);
#else
    for (unsigned i = 0; i < SYDO_FIELD_WORDS; ++i) a.word[i] &= mask;
#endif
    return a;
}

static inline sydo_field field_one(void) {
    sydo_field x = {{1}};
    return x;
}

sydo_field field_read(const uint8_t *bytes);
void field_write(uint8_t *bytes, sydo_field x);
sydo_field field_shift(sydo_field a);
#ifdef SYDO_AVX2
#include "avx2/fields.h"
#else
sydo_field field_mul(sydo_field a, sydo_field b);
sydo_field field_mul64(sydo_field a, uint64_t b);
uint64_t field64_mul(uint64_t a, uint64_t b);
typedef sydo_field sydo_field_product;
static inline sydo_field_product field_product_zero(void) { return field_zero(); }
static inline sydo_field_product field_product_add(sydo_field_product a, sydo_field_product b) { return field_add(a,b); }
static inline sydo_field_product field_product_mul(sydo_field a, sydo_field b) { return field_mul(a,b); }
static inline sydo_field field_product_reduce(sydo_field_product p) { return p; }
#endif

#endif
