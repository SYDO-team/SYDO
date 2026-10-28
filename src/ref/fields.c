#include "fields.h"

/* Separate the input polynomials into residue classes modulo four.
 * Each integer-product coefficient has at most eight summands, so its
 * carries stay within the four-bit spacing. Extract the parity bits. */
static uint64_t polynomial32(uint32_t a, uint32_t b) {
    const uint64_t lanes = UINT64_C(0x1111111111111111);
    uint64_t a0 = a & lanes, a1 = (a >> 1) & lanes;
    uint64_t a2 = (a >> 2) & lanes, a3 = (a >> 3) & lanes;
    uint64_t b0 = b & lanes, b1 = (b >> 1) & lanes;
    uint64_t b2 = (b >> 2) & lanes, b3 = (b >> 3) & lanes;
    uint64_t l0 = a0 * b0, l2 = a1 * b1;
    uint64_t l1 = (a0 ^ a1) * (b0 ^ b1) ^ l0 ^ l2;
    uint64_t h0 = a2 * b2, h2 = a3 * b3;
    uint64_t h1 = (a2 ^ a3) * (b2 ^ b3) ^ h0 ^ h2;
    uint64_t m0 = (a0 ^ a2) * (b0 ^ b2), m2 = (a1 ^ a3) * (b1 ^ b3);
    uint64_t m1 = (a0 ^ a1 ^ a2 ^ a3) * (b0 ^ b1 ^ b2 ^ b3) ^ m0 ^ m2;
    return (l0 & lanes) ^ ((l1 & lanes) << 1) ^
           (((l2 ^ m0 ^ l0 ^ h0) & lanes) << 2) ^
           (((m1 ^ l1 ^ h1) & lanes) << 3) ^
           (((h0 ^ m2 ^ l2 ^ h2) & lanes) << 4) ^
           ((h1 & lanes) << 5) ^ ((h2 & lanes) << 6);
}

static void polynomial64(uint64_t a, uint64_t b, uint64_t out[2]) {
    uint64_t lo = polynomial32((uint32_t)a, (uint32_t)b);
    uint64_t hi = polynomial32((uint32_t)(a >> 32), (uint32_t)(b >> 32));
    uint64_t cross = polynomial32((uint32_t)a ^ (uint32_t)(a >> 32),
                                  (uint32_t)b ^ (uint32_t)(b >> 32)) ^ lo ^ hi;
    out[0] = lo ^ (cross << 32);
    out[1] = hi ^ (cross >> 32);
}

#if SYDO_LAMBDA != 160
static void polynomial128(const uint64_t a[2], const uint64_t b[2], uint64_t out[4]) {
    uint64_t low[2], high[2], cross[2];
    polynomial64(a[0], b[0], low);
    polynomial64(a[1], b[1], high);
    polynomial64(a[0] ^ a[1], b[0] ^ b[1], cross);
    out[0] = low[0];
    out[1] = low[1] ^ cross[0] ^ low[0] ^ high[0];
    out[2] = high[0] ^ cross[1] ^ low[1] ^ high[1];
    out[3] = high[1];
}

static void polynomial256(const uint64_t a[4], const uint64_t b[4], uint64_t out[8]) {
    uint64_t low[4], high[4], cross[4], ax[2], bx[2];
    for (unsigned i = 0; i < 2; ++i) { ax[i] = a[i] ^ a[i+2]; bx[i] = b[i] ^ b[i+2]; }
    polynomial128(a, b, low); polynomial128(a+2, b+2, high); polynomial128(ax, bx, cross);
    memset(out, 0, 8u * sizeof(*out));
    for (unsigned i = 0; i < 4; ++i) {
        out[i] ^= low[i]; out[i+4] ^= high[i]; out[i+2] ^= cross[i] ^ low[i] ^ high[i];
    }
}

#if SYDO_LAMBDA == 512
static void polynomial512(const uint64_t a[8], const uint64_t b[8], uint64_t out[16]) {
    uint64_t low[8], high[8], cross[8], ax[4], bx[4];
    for (unsigned i = 0; i < 4; ++i) { ax[i] = a[i] ^ a[i+4]; bx[i] = b[i] ^ b[i+4]; }
    polynomial256(a, b, low); polynomial256(a+4, b+4, high); polynomial256(ax, bx, cross);
    memset(out, 0, 16u * sizeof(*out));
    for (unsigned i = 0; i < 8; ++i) {
        out[i] ^= low[i]; out[i+8] ^= high[i]; out[i+4] ^= cross[i] ^ low[i] ^ high[i];
    }
}
#endif

static sydo_field reduce_words(uint64_t *product, unsigned count) {
    const unsigned shifts[3] = {2,5, SYDO_LAMBDA == 512 ? 8u : 10u};
    for (unsigned i = count; i-- > SYDO_FIELD_WORDS;) {
        uint64_t high = product[i]; product[i] = 0;
        product[i-SYDO_FIELD_WORDS] ^= high;
        for (unsigned j = 0; j < 3; ++j) {
            product[i-SYDO_FIELD_WORDS] ^= high << shifts[j];
            product[i-SYDO_FIELD_WORDS+1u] ^= high >> (64u-shifts[j]);
        }
    }
    sydo_field result;
    memcpy(result.word, product, sizeof(result.word));
    return result;
}
#endif

sydo_field field_mul(sydo_field a, sydo_field b) {
#if SYDO_LAMBDA == 160
    uint64_t d0[2], d1[2], cross01[2], cross02[2], cross12[2];
    uint64_t d2 = polynomial32((uint32_t)a.word[2], (uint32_t)b.word[2]);
    polynomial64(a.word[0], b.word[0], d0);
    polynomial64(a.word[1], b.word[1], d1);
    polynomial64(a.word[0] ^ a.word[1], b.word[0] ^ b.word[1], cross01);
    polynomial64(a.word[0] ^ a.word[2], b.word[0] ^ b.word[2], cross02);
    polynomial64(a.word[1] ^ a.word[2], b.word[1] ^ b.word[2], cross12);
    uint64_t p[6] = {
        d0[0],
        d0[1] ^ cross01[0] ^ d0[0] ^ d1[0],
        d1[0] ^ cross01[1] ^ d0[1] ^ d1[1] ^ cross02[0] ^ d0[0] ^ d2,
        d1[1] ^ cross02[1] ^ d0[1] ^ cross12[0] ^ d1[0] ^ d2,
        d2 ^ cross12[1] ^ d1[1],
        0
    };
    /* x^160 = x^5 + x^4 + x^3 + 1. Two folds suffice. */
    for (unsigned fold = 0; fold < 2; ++fold) {
        uint64_t high[3];
        for (unsigned i = 0; i < 3; ++i)
            high[i] = (p[i + 2] >> 32) ^ (p[i + 3] << 32);
        p[2] &= UINT32_MAX;
        p[3] = p[4] = p[5] = 0;
        const unsigned powers[4] = {0, 3, 4, 5};
        for (unsigned k = 0; k < 4; ++k)
            for (unsigned i = 0; i < 3; ++i) {
                p[i] ^= high[i] << powers[k];
                if (powers[k]) p[i + 1] ^= high[i] >> (64 - powers[k]);
            }
    }
    sydo_field r = {{p[0], p[1], p[2]}};
    return r;
#else
    uint64_t product[2u * SYDO_FIELD_WORDS];
#if SYDO_LAMBDA == 512
    polynomial512(a.word, b.word, product);
#else
    polynomial256(a.word, b.word, product);
#endif
    return reduce_words(product, 2u * SYDO_FIELD_WORDS);
#endif
}

uint64_t field64_mul(uint64_t a, uint64_t b) {
    uint64_t product[2], overflow;
    polynomial64(a, b, product);
    /* x^64 = x^4 + x^3 + x + 1. */
    overflow = (product[1] >> 60) ^ (product[1] >> 61) ^ (product[1] >> 63);
    return product[0] ^ product[1] ^ (product[1] << 1) ^
           (product[1] << 3) ^ (product[1] << 4) ^ overflow ^
           (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
}

sydo_field field_mul64(sydo_field a, uint64_t b) {
#if SYDO_LAMBDA == 160
    uint64_t d0[2], d1[2];
    polynomial64(a.word[0], b, d0);
    polynomial64(a.word[1], b, d1);
    uint64_t low = polynomial32((uint32_t)a.word[2], (uint32_t)b);
    uint64_t high = polynomial32((uint32_t)a.word[2], (uint32_t)(b >> 32));
    uint64_t p2 = d1[1] ^ low ^ (high << 32), p3 = high >> 32;
    uint64_t h0 = (p2 >> 32) ^ (p3 << 32), h1 = p3 >> 32;
    sydo_field result = {{
        d0[0] ^ h0 ^ (h0 << 3) ^ (h0 << 4) ^ (h0 << 5),
        d0[1] ^ d1[0] ^ h1 ^ (h1 << 3) ^ (h1 << 4) ^ (h1 << 5) ^
            (h0 >> 61) ^ (h0 >> 60) ^ (h0 >> 59),
        (p2 & UINT32_MAX) ^ (h1 >> 61) ^ (h1 >> 60) ^ (h1 >> 59)
    }};
    return result;
#else
    uint64_t product[SYDO_FIELD_WORDS + 1u] = {0};
    for (unsigned i = 0; i < SYDO_FIELD_WORDS; ++i) {
        uint64_t part[2]; polynomial64(a.word[i], b, part);
        product[i] ^= part[0]; product[i+1u] ^= part[1];
    }
    return reduce_words(product, SYDO_FIELD_WORDS + 1u);
#endif
}
