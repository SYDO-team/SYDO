#include "fields.h"
#include "bytes.h"

sydo_field field_read(const uint8_t *bytes) {
    sydo_field x = field_zero();
#ifdef SYDO_AVX2
    for (unsigned v = 0; v < SYDO_SEED_BYTES / 16u; ++v)
        x.vector[v] = _mm_loadu_si128((const __m128i *)(const void *)(bytes + 16u * v));
#if SYDO_SEED_BYTES % 16u
    x.vector[SYDO_SEED_BYTES / 16u] = _mm_cvtsi32_si128((int)sydo_load32(bytes + SYDO_SEED_BYTES / 16u * 16u));
#endif
#else
    for (unsigned w = 0; w < SYDO_SEED_BYTES / 8u; ++w)
        x.word[w] = (uint64_t)sydo_load32(bytes + 8u * w) |
                    ((uint64_t)sydo_load32(bytes + 8u * w + 4u) << 32);
#if SYDO_SEED_BYTES % 8u
    x.word[SYDO_SEED_BYTES / 8u] = sydo_load32(bytes + SYDO_SEED_BYTES / 8u * 8u);
#endif
#endif
    return x;
}

void field_write(uint8_t *bytes, sydo_field x) {
#ifdef SYDO_AVX2
    for (unsigned v = 0; v < SYDO_SEED_BYTES / 16u; ++v)
        _mm_storeu_si128((__m128i *)(void *)(bytes + 16u * v), x.vector[v]);
#if SYDO_SEED_BYTES % 16u
    sydo_store32(bytes + SYDO_SEED_BYTES / 16u * 16u, (uint32_t)_mm_cvtsi128_si32(x.vector[SYDO_SEED_BYTES / 16u]));
#endif
#else
    for (unsigned w = 0; w < SYDO_SEED_BYTES / 8u; ++w) {
        sydo_store32(bytes + 8u * w, (uint32_t)x.word[w]);
        sydo_store32(bytes + 8u * w + 4u, (uint32_t)(x.word[w] >> 32));
    }
#if SYDO_SEED_BYTES % 8u
    sydo_store32(bytes + SYDO_SEED_BYTES / 8u * 8u, (uint32_t)x.word[SYDO_SEED_BYTES / 8u]);
#endif
#endif
}

sydo_field field_shift(sydo_field a) {
    uint64_t carry = a.word[SYDO_FIELD_WORDS - 1u] >> ((SYDO_LAMBDA - 1u) % 64u);
    for (unsigned w = SYDO_FIELD_WORDS - 1u; w > 0; --w)
        a.word[w] = (a.word[w] << 1) | (a.word[w-1u] >> 63);
    a.word[0] = (a.word[0] << 1) ^ ((UINT64_C(0) - carry) & SYDO_FIELD_MODULUS);
#if SYDO_LAMBDA % 64u
    a.word[SYDO_FIELD_WORDS - 1u] &= (UINT64_C(1) << (SYDO_LAMBDA % 64u)) - 1u;
#endif
    return a;
}
