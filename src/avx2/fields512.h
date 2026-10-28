#ifndef SYDO_AVX2_FIELDS512_H
#define SYDO_AVX2_FIELDS512_H

static inline __attribute__((always_inline)) __m128i polynomial64_cross(__m128i a, __m128i b) {
    __m128i split = _mm_alignr_epi8(b,a,8);
    return _mm_clmulepi64_si128(_mm_xor_si128(a,split),_mm_xor_si128(b,split),0x10);
}

static inline __attribute__((always_inline)) void polynomial256_coefficients(
        __m128i out[7], const __m128i a[2], const __m128i b[2]) {
    __m128i d0 = _mm_clmulepi64_si128(a[0],b[0],0), d1 = _mm_clmulepi64_si128(a[0],b[0],0x11);
    __m128i d2 = _mm_clmulepi64_si128(a[1],b[1],0), d3 = _mm_clmulepi64_si128(a[1],b[1],0x11);
    __m128i sl = polynomial64_cross(a[0],b[0]);
    __m128i sh = polynomial64_cross(a[1],b[1]);
    __m128i ax = _mm_xor_si128(a[0],a[1]), bx = _mm_xor_si128(b[0],b[1]);
    __m128i m0 = _mm_clmulepi64_si128(ax,bx,0), m1 = _mm_clmulepi64_si128(ax,bx,0x11);
    __m128i sm = polynomial64_cross(ax,bx);
    out[0] = d0; out[6] = d3;
    out[1] = _mm_xor_si128(sl,_mm_xor_si128(d0,d1));
    out[5] = _mm_xor_si128(sh,_mm_xor_si128(d2,d3));
    __m128i middle = _mm_xor_si128(d1,d2);
    out[2] = _mm_xor_si128(m0,_mm_xor_si128(d0,middle));
    out[4] = _mm_xor_si128(m1,_mm_xor_si128(d3,middle));
    out[3] = _mm_xor_si128(sm,_mm_xor_si128(_mm_xor_si128(m0,m1),_mm_xor_si128(out[1],out[5])));
}

typedef struct { __m128i vector[8]; } sydo_field_product;

static inline sydo_field_product field_product_zero(void) {
    sydo_field_product p;
    for (unsigned i = 0; i < 8; ++i) p.vector[i] = _mm_setzero_si128();
    return p;
}

static inline sydo_field_product field_product_add(sydo_field_product a, sydo_field_product b) {
    for (unsigned i = 0; i < 8; ++i) a.vector[i] = _mm_xor_si128(a.vector[i],b.vector[i]);
    return a;
}

static inline __attribute__((always_inline)) sydo_field_product field_product_mul(sydo_field a, sydo_field b) {
    __m128i low[7], high[7], cross[7], ax[2], bx[2], coefficients[15];
    for (unsigned i = 0; i < 2; ++i) { ax[i] = _mm_xor_si128(a.vector[i],a.vector[i+2]); bx[i] = _mm_xor_si128(b.vector[i],b.vector[i+2]); }
    polynomial256_coefficients(low,a.vector,b.vector);
    polynomial256_coefficients(high,a.vector+2,b.vector+2);
    polynomial256_coefficients(cross,ax,bx);
    for (unsigned i = 0; i < 15; ++i) coefficients[i] = _mm_setzero_si128();
    for (unsigned i = 0; i < 7; ++i) {
        coefficients[i] = _mm_xor_si128(coefficients[i],low[i]);
        coefficients[i+8] = _mm_xor_si128(coefficients[i+8],high[i]);
        coefficients[i+4] = _mm_xor_si128(coefficients[i+4],_mm_xor_si128(cross[i],_mm_xor_si128(low[i],high[i])));
    }
    sydo_field_product out;
    out.vector[0] = _mm_xor_si128(coefficients[0],_mm_slli_si128(coefficients[1],8));
    for (unsigned i = 1; i < 7; ++i)
        out.vector[i] = _mm_xor_si128(coefficients[2u*i],_mm_alignr_epi8(coefficients[2u*i+1u],coefficients[2u*i-1u],8));
    out.vector[7] = _mm_xor_si128(coefficients[14],_mm_srli_si128(coefficients[13],8));
    return out;
}

static inline __attribute__((always_inline)) sydo_field field_product_reduce(sydo_field_product p) {
    const __m128i modulus = _mm_cvtsi32_si128(SYDO_FIELD_MODULUS);
    __m128i q7 = _mm_clmulepi64_si128(p.vector[7],modulus,1);
    __m128i first = _mm_xor_si128(p.vector[4],_mm_srli_si128(q7,8));
    __m128i q0 = _mm_clmulepi64_si128(first,modulus,0);
    __m128i q1 = _mm_clmulepi64_si128(p.vector[4],modulus,1);
    __m128i q2 = _mm_clmulepi64_si128(p.vector[5],modulus,0);
    __m128i q3 = _mm_clmulepi64_si128(p.vector[5],modulus,1);
    __m128i q4 = _mm_clmulepi64_si128(p.vector[6],modulus,0);
    __m128i q5 = _mm_clmulepi64_si128(p.vector[6],modulus,1);
    __m128i q6 = _mm_clmulepi64_si128(p.vector[7],modulus,0);
    sydo_field out;
    out.vector[0] = _mm_xor_si128(p.vector[0],_mm_xor_si128(q0,_mm_slli_si128(q1,8)));
    out.vector[1] = _mm_xor_si128(p.vector[1],_mm_xor_si128(_mm_srli_si128(q1,8),_mm_xor_si128(q2,_mm_slli_si128(q3,8))));
    out.vector[2] = _mm_xor_si128(p.vector[2],_mm_xor_si128(_mm_srli_si128(q3,8),_mm_xor_si128(q4,_mm_slli_si128(q5,8))));
    out.vector[3] = _mm_xor_si128(p.vector[3],_mm_xor_si128(_mm_srli_si128(q5,8),_mm_xor_si128(q6,_mm_slli_si128(q7,8))));
    return out;
}

static inline __attribute__((always_inline)) sydo_field field_mul(sydo_field a, sydo_field b) {
    return field_product_reduce(field_product_mul(a,b));
}

static inline __attribute__((always_inline)) sydo_field field_mul64(sydo_field a, uint64_t b) {
    __m128i scalar = _mm_cvtsi64_si128((long long)b), carry = _mm_setzero_si128();
    sydo_field out;
    for (unsigned i = 0; i < 4; ++i) {
        __m128i low = _mm_clmulepi64_si128(a.vector[i],scalar,0);
        __m128i high = _mm_clmulepi64_si128(a.vector[i],scalar,1);
        out.vector[i] = _mm_xor_si128(carry,_mm_xor_si128(low,_mm_slli_si128(high,8)));
        carry = _mm_srli_si128(high,8);
    }
    out.vector[0] = _mm_xor_si128(out.vector[0],_mm_clmulepi64_si128(carry,_mm_cvtsi32_si128(SYDO_FIELD_MODULUS),0));
    return out;
}

#endif
