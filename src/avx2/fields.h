#ifndef SYDO_AVX2_FIELDS_H
#define SYDO_AVX2_FIELDS_H

#include <immintrin.h>

static inline __attribute__((always_inline)) void polynomial64(uint64_t a, uint64_t b, uint64_t out[2]) {
    __m128i product = _mm_clmulepi64_si128(_mm_set_epi64x(0, (long long)a),
                                        _mm_set_epi64x(0, (long long)b), 0);
    _mm_storeu_si128((__m128i *)(void *)out, product);
}


#if SYDO_LAMBDA == 160
static inline __attribute__((always_inline)) sydo_field field_reduce(__m128i low, __m128i middle, __m128i high) {
    __m128i h = _mm_xor_si128(_mm_srli_si128(middle, 4), _mm_slli_si128(high, 12));
    const __m128i modulus = _mm_set_epi64x(0, 0x39);
    __m128i r0 = _mm_clmulepi64_si128(h, modulus, 0);
    __m128i r1 = _mm_clmulepi64_si128(h, modulus, 1);
    __m128i r2 = _mm_clmulepi64_si128(_mm_srli_epi64(high,32), modulus, 0);
    const __m128i bottom = _mm_set_epi64x(0,UINT32_MAX);
    __m128i top = _mm_xor_si128(_mm_and_si128(middle,bottom), _mm_xor_si128(_mm_srli_si128(r1,8),r2));
    __m128i last = _mm_clmulepi64_si128(_mm_srli_epi64(top,32),modulus,0);
    sydo_field result = field_zero();
    result.vector[0] = _mm_xor_si128(_mm_xor_si128(low,r0),_mm_xor_si128(_mm_slli_si128(r1,8),last));
    result.vector[1] = _mm_and_si128(top,bottom);
    return result;
}

typedef struct { __m128i low, middle, high; } sydo_field_product;

static inline sydo_field_product field_product_zero(void) {
    sydo_field_product p = {_mm_setzero_si128(), _mm_setzero_si128(), _mm_setzero_si128()};
    return p;
}

static inline sydo_field_product field_product_add(sydo_field_product a, sydo_field_product b) {
    sydo_field_product p = {_mm_xor_si128(a.low,b.low), _mm_xor_si128(a.middle,b.middle), _mm_xor_si128(a.high,b.high)};
    return p;
}

static inline __attribute__((always_inline)) sydo_field field_product_reduce(sydo_field_product p) {
    return field_reduce(p.low, p.middle, p.high);
}

static inline __attribute__((always_inline)) sydo_field_product field_product_mul(sydo_field a, sydo_field b) {
    __m128i al = a.vector[0], bl = b.vector[0];
    __m128i ah = a.vector[1], bh = b.vector[1];
    __m128i as = _mm_shuffle_epi32(al,0x4e), bs = _mm_shuffle_epi32(bl,0x4e);
    __m128i d0 = _mm_clmulepi64_si128(al,bl,0);
    __m128i d1 = _mm_clmulepi64_si128(al,bl,0x11);
    __m128i d2 = _mm_clmulepi64_si128(ah,bh,0);
    __m128i c01 = _mm_xor_si128(_mm_clmulepi64_si128(_mm_xor_si128(al,as),_mm_xor_si128(bl,bs),0), _mm_xor_si128(d0,d1));
    __m128i c02 = _mm_xor_si128(_mm_clmulepi64_si128(_mm_xor_si128(al,ah),_mm_xor_si128(bl,bh),0), _mm_xor_si128(d0,d2));
    __m128i c12 = _mm_xor_si128(_mm_clmulepi64_si128(_mm_xor_si128(as,ah),_mm_xor_si128(bs,bh),0), _mm_xor_si128(d1,d2));
    __m128i low = _mm_xor_si128(d0, _mm_slli_si128(c01, 8));
    __m128i middle = _mm_xor_si128(_mm_xor_si128(d1, c02), _mm_xor_si128(_mm_srli_si128(c01, 8), _mm_slli_si128(c12, 8)));
    __m128i high = _mm_xor_si128(d2, _mm_srli_si128(c12, 8));
    sydo_field_product product = {low, middle, high};
    return product;
}

static inline __attribute__((always_inline)) sydo_field field_mul(sydo_field a, sydo_field b) {
    return field_product_reduce(field_product_mul(a, b));
}

static inline __attribute__((always_inline)) sydo_field field_mul64(sydo_field a, uint64_t b) {
    __m128i scalar = _mm_set_epi64x(0,(long long)b);
    __m128i d0 = _mm_clmulepi64_si128(a.vector[0],scalar,0);
    __m128i d1 = _mm_clmulepi64_si128(a.vector[0],scalar,1);
    __m128i d2 = _mm_clmulepi64_si128(a.vector[1],scalar,0);
    __m128i low = _mm_xor_si128(d0,_mm_slli_si128(d1,8));
    __m128i middle = _mm_xor_si128(_mm_srli_si128(d1,8),d2);
    __m128i h = _mm_srli_si128(middle,4);
    low = _mm_xor_si128(low,_mm_clmulepi64_si128(h,_mm_set_epi64x(0,0x39),0));
    sydo_field result = field_zero();
    result.vector[0] = low;
    result.vector[1] = _mm_and_si128(middle,_mm_set_epi64x(0,UINT32_MAX));
    return result;
}

#elif SYDO_LAMBDA == 512
#include "fields512.h"
#else
typedef struct { __m128i vector[4]; } sydo_field_product;

static inline sydo_field_product field_product_zero(void) {
    sydo_field_product p;
    for (unsigned i = 0; i < 4; ++i) p.vector[i] = _mm_setzero_si128();
    return p;
}

static inline sydo_field_product field_product_add(sydo_field_product a, sydo_field_product b) {
    for (unsigned i = 0; i < 4; ++i) a.vector[i] = _mm_xor_si128(a.vector[i],b.vector[i]);
    return a;
}

static inline __attribute__((always_inline)) sydo_field_product field_product_mul(sydo_field a, sydo_field b) {
    __m128i al = a.vector[0], ah = a.vector[1], bl = b.vector[0], bh = b.vector[1];
    __m128i d0 = _mm_clmulepi64_si128(al,bl,0), d1 = _mm_clmulepi64_si128(al,bl,0x11);
    __m128i d2 = _mm_clmulepi64_si128(ah,bh,0), d3 = _mm_clmulepi64_si128(ah,bh,0x11);
    __m128i sl = _mm_clmulepi64_si128(_mm_xor_si128(al,_mm_shuffle_epi32(al,0x4e)),
                                     _mm_xor_si128(bl,_mm_shuffle_epi32(bl,0x4e)),0);
    __m128i sh = _mm_clmulepi64_si128(_mm_xor_si128(ah,_mm_shuffle_epi32(ah,0x4e)),
                                     _mm_xor_si128(bh,_mm_shuffle_epi32(bh,0x4e)),0);
    __m128i ax = _mm_xor_si128(al,ah), bx = _mm_xor_si128(bl,bh);
    __m128i m0 = _mm_clmulepi64_si128(ax,bx,0), m1 = _mm_clmulepi64_si128(ax,bx,0x11);
    __m128i sm = _mm_clmulepi64_si128(_mm_xor_si128(ax,_mm_shuffle_epi32(ax,0x4e)),
                                     _mm_xor_si128(bx,_mm_shuffle_epi32(bx,0x4e)),0);
    __m128i c1 = _mm_xor_si128(sl,_mm_xor_si128(d0,d1));
    __m128i c5 = _mm_xor_si128(sh,_mm_xor_si128(d2,d3));
    __m128i shared = _mm_xor_si128(d1,d2);
    __m128i c2 = _mm_xor_si128(m0,_mm_xor_si128(d0,shared));
    __m128i c4 = _mm_xor_si128(m1,_mm_xor_si128(d3,shared));
    __m128i c3 = _mm_xor_si128(sm,_mm_xor_si128(_mm_xor_si128(m0,m1),_mm_xor_si128(c1,c5)));
    sydo_field_product result = {{_mm_xor_si128(d0,_mm_slli_si128(c1,8)),
        _mm_xor_si128(c2,_mm_alignr_epi8(c3,c1,8)),
        _mm_xor_si128(c4,_mm_alignr_epi8(c5,c3,8)),
        _mm_xor_si128(d3,_mm_srli_si128(c5,8))}};
    return result;
}

static inline __attribute__((always_inline)) sydo_field field_product_reduce(sydo_field_product p) {
    const __m128i modulus = _mm_cvtsi32_si128(SYDO_FIELD_MODULUS);
    __m128i q3 = _mm_clmulepi64_si128(p.vector[3],modulus,1);
    __m128i first = _mm_xor_si128(p.vector[2],_mm_srli_si128(q3,8));
    __m128i q0 = _mm_clmulepi64_si128(first,modulus,0);
    __m128i q1 = _mm_clmulepi64_si128(p.vector[2],modulus,1);
    __m128i q2 = _mm_clmulepi64_si128(p.vector[3],modulus,0);
    sydo_field result;
    result.vector[0] = _mm_xor_si128(p.vector[0],_mm_xor_si128(q0,_mm_slli_si128(q1,8)));
    result.vector[1] = _mm_xor_si128(p.vector[1],_mm_xor_si128(_mm_srli_si128(q1,8),_mm_xor_si128(q2,_mm_slli_si128(q3,8))));
    return result;
}

static inline __attribute__((always_inline)) sydo_field field_mul(sydo_field a, sydo_field b) {
    return field_product_reduce(field_product_mul(a,b));
}

static inline __attribute__((always_inline)) sydo_field field_mul64(sydo_field a, uint64_t b) {
    __m128i scalar = _mm_cvtsi64_si128((long long)b);
    __m128i d0 = _mm_clmulepi64_si128(a.vector[0],scalar,0);
    __m128i d1 = _mm_clmulepi64_si128(a.vector[0],scalar,1);
    __m128i d2 = _mm_clmulepi64_si128(a.vector[1],scalar,0);
    __m128i d3 = _mm_clmulepi64_si128(a.vector[1],scalar,1);
    __m128i high = _mm_clmulepi64_si128(_mm_srli_si128(d3,8),_mm_cvtsi32_si128(SYDO_FIELD_MODULUS),0);
    sydo_field result;
    result.vector[0] = _mm_xor_si128(_mm_xor_si128(d0,_mm_slli_si128(d1,8)),high);
    result.vector[1] = _mm_xor_si128(_mm_xor_si128(_mm_srli_si128(d1,8),d2),_mm_slli_si128(d3,8));
    return result;
}
#endif

static inline __attribute__((always_inline)) uint64_t field64_mul(uint64_t a, uint64_t b) {
    uint64_t p[2];
    polynomial64(a, b, p);
    uint64_t overflow = (p[1] >> 60) ^ (p[1] >> 61) ^ (p[1] >> 63);
    return p[0] ^ p[1] ^ (p[1] << 1) ^ (p[1] << 3) ^ (p[1] << 4) ^
           overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
}

#endif
