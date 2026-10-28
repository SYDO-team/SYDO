#include "cipher.h"
#include "bytes.h"
#include <immintrin.h>
#include <string.h>

static const uint8_t rotate_subword[16] = {13, 10, 7, 0, 1, 14, 11, 4, 5, 2, 15, 8, 9, 6, 3, 12};
static const uint8_t subword_order[16] = {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};
#if SYDO_CIPHER_BLOCK_BYTES == 24u
static const uint8_t rijndael_rows[3][16] = {
    {0, 1, 2, 11, 4, 5, 6, 7, 8, 9, 10, 3, 12, 13, 14, 15},
    {0, 255, 255, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0},
    {255, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};
#else
#define ROW_SOURCE(c,r,s) (4u*(((c)+4u-(r)+(s))%4u)+(r))
#define ROW_CROSS(c,r,s) ((uint8_t)(0u-((((c)+4u-(r))%4u+(s))/4u)))
#define ROW_MAP(c) ROW_SOURCE(c,0,0),ROW_SOURCE(c,1,1),ROW_SOURCE(c,2,3),ROW_SOURCE(c,3,4)
#define ROW_SELECT(c) ROW_CROSS(c,0,0),ROW_CROSS(c,1,1),ROW_CROSS(c,2,3),ROW_CROSS(c,3,4)
static const uint8_t rijndael_rows[3][16] = {
    {ROW_MAP(0),ROW_MAP(1),ROW_MAP(2),ROW_MAP(3)},
    {ROW_SELECT(0),ROW_SELECT(1),ROW_SELECT(2),ROW_SELECT(3)},
    {0}
};
#undef ROW_SOURCE
#undef ROW_CROSS
#undef ROW_MAP
#undef ROW_SELECT
#endif

static inline void rijndael_round(__m128i *lo, __m128i *hi, __m128i kl, __m128i kh,
                                 const __m128i mask[3], unsigned last) {
#if SYDO_CIPHER_BLOCK_BYTES == 24u
    __m128i shuffled = _mm_shuffle_epi8(*lo, mask[0]);
    __m128i a = _mm_blendv_epi8(shuffled, *hi, mask[1]);
    __m128i b = _mm_blendv_epi8(shuffled, *hi, mask[2]);
    b = _mm_unpacklo_epi64(b, b);
#else
    __m128i shuffled_lo = _mm_shuffle_epi8(*lo,mask[0]);
    __m128i shuffled_hi = _mm_shuffle_epi8(*hi,mask[0]);
    __m128i a = _mm_blendv_epi8(shuffled_lo,shuffled_hi,mask[1]);
    __m128i b = _mm_blendv_epi8(shuffled_hi,shuffled_lo,mask[1]);
#endif
    *lo = last ? _mm_aesenclast_si128(a, kl) : _mm_aesenc_si128(a, kl);
    *hi = last ? _mm_aesenclast_si128(b, kh) : _mm_aesenc_si128(b, kh);
}

static inline __m128i substitute_word(__m128i word) {
    return _mm_shuffle_epi8(_mm_aesenclast_si128(word,_mm_setzero_si128()),
                           _mm_loadu_si128((const __m128i *)(const void *)subword_order));
}

static inline void rijndael_expand_round(__m128i words[SYDO_CIPHER_KEY_WORDS], __m128i rotate, uint8_t *rcon) {
    __m128i temp = _mm_shuffle_epi8(_mm_aesenclast_si128(words[SYDO_CIPHER_KEY_WORDS-1u], _mm_setzero_si128()), rotate);
    temp = _mm_xor_si128(temp, _mm_set1_epi32(*rcon));
    *rcon = (uint8_t)((*rcon << 1) ^ ((0u - (*rcon >> 7)) & 0x1bu));
    words[0] = _mm_xor_si128(words[0], temp);
    for (unsigned w = 1; w < SYDO_CIPHER_KEY_WORDS; ++w) {
        temp = words[w-1u];
        if (SYDO_CIPHER_KEY_WORDS > 6u && w == 4u) temp = substitute_word(temp);
        words[w] = _mm_xor_si128(words[w],temp);
    }
}

static inline void store_words(uint8_t *output, size_t stride, size_t count,
                                const __m128i *words, unsigned width) {
    __m128i a = _mm_unpacklo_epi32(words[0], words[1]);
    __m128i b = _mm_unpacklo_epi32(words[2], words[3]);
    __m128i c = _mm_unpackhi_epi32(words[0], words[1]);
    __m128i d = _mm_unpackhi_epi32(words[2], words[3]);
    __m128i t0 = _mm_setzero_si128(), t1 = t0, t2 = t0, t3 = t0;
    if (width != 4u) {
#if SYDO_CIPHER_KEY_WORDS == 6u
        t0 = _mm_unpacklo_epi32(words[4], words[5]);
        t1 = _mm_srli_si128(t0,8);
        t2 = _mm_unpackhi_epi32(words[4], words[5]);
        t3 = _mm_srli_si128(t2,8);
#else
        __m128i e = _mm_unpacklo_epi32(words[4],words[5]);
        __m128i f = _mm_unpacklo_epi32(words[6],words[7]);
        __m128i g = _mm_unpackhi_epi32(words[4],words[5]);
        __m128i h = _mm_unpackhi_epi32(words[6],words[7]);
        t0 = _mm_unpacklo_epi64(e,f); t1 = _mm_unpackhi_epi64(e,f);
        t2 = _mm_unpacklo_epi64(g,h); t3 = _mm_unpackhi_epi64(g,h);
#endif
    }
#define STORE_KEY(j,value,tail) do { \
    if (count > (j)) { \
        uint8_t *destination = output + (j) * stride; \
        _mm_storeu_si128((__m128i *)(void *)destination,(value)); \
        if (width != 4u) memcpy(destination+16,&(tail),SYDO_CIPHER_BLOCK_BYTES-16u); \
    } \
} while (0)
    STORE_KEY(0,_mm_unpacklo_epi64(a,b),t0);
    STORE_KEY(1,_mm_unpackhi_epi64(a,b),t1);
    STORE_KEY(2,_mm_unpacklo_epi64(c,d),t2);
    STORE_KEY(3,_mm_unpackhi_epi64(c,d),t3);
#undef STORE_KEY
}

static inline void store_round(sydo_cipher_keys *expanded, size_t first, size_t count,
                                unsigned r, const __m128i *words, unsigned width) {
    size_t stride = (SYDO_CIPHER_ROUNDS+1u)*expanded->block_bytes;
    store_words((uint8_t *)(void *)expanded->keys+first*stride+r*expanded->block_bytes,stride,count,words,width);
}

static inline void transpose_four(__m128i output[4], const __m128i input[4]) {
    __m128i a = _mm_unpacklo_epi32(input[0],input[1]);
    __m128i b = _mm_unpackhi_epi32(input[0],input[1]);
    __m128i c = _mm_unpacklo_epi32(input[2],input[3]);
    __m128i d = _mm_unpackhi_epi32(input[2],input[3]);
    output[0] = _mm_unpacklo_epi64(a,c); output[1] = _mm_unpackhi_epi64(a,c);
    output[2] = _mm_unpacklo_epi64(b,d); output[3] = _mm_unpackhi_epi64(b,d);
}

static inline void transpose_keys(__m128i words[SYDO_CIPHER_KEY_WORDS], __m128i low[4], __m128i high[4]) {
    transpose_four(words,low);
#if SYDO_CIPHER_KEY_WORDS == 6u
    __m128i a = _mm_unpacklo_epi64(high[0],high[1]), b = _mm_unpacklo_epi64(high[2],high[3]);
    words[4] = _mm_unpacklo_epi64(_mm_shuffle_epi32(a,0x88),_mm_shuffle_epi32(b,0x88));
    words[5] = _mm_unpacklo_epi64(_mm_shuffle_epi32(a,0xdd),_mm_shuffle_epi32(b,0xdd));
#else
    transpose_four(words+4,high);
#endif
    volatile __m128i *secret_low = low, *secret_high = high;
    for (unsigned j = 0; j < 4; ++j) { secret_low[j] = _mm_setzero_si128(); secret_high[j] = _mm_setzero_si128(); }
}

static inline __m128i load_tail(const uint8_t *input) {
#if SYDO_CIPHER_BLOCK_BYTES == 24u
    return _mm_loadl_epi64((const __m128i *)(const void *)input);
#else
    return _mm_loadu_si128((const __m128i *)(const void *)input);
#endif
}

static inline __m128i counter_tail(const uint8_t iv[SYDO_SEED_BYTES], uint32_t tweak) {
#if SYDO_SEED_BYTES == 20u
    return _mm_cvtsi32_si128((int)(sydo_load32(iv+16)+tweak));
#else
    return _mm_add_epi32(_mm_loadu_si128((const __m128i *)(const void *)(iv+16)),_mm_set_epi32((int)tweak,0,0,0));
#endif
}

static inline void load_keys(__m128i words[SYDO_CIPHER_KEY_WORDS], const uint8_t *keys,
                              size_t stride, size_t count) {
    __m128i low[4], high[4];
    for (unsigned j = 0; j < 4; ++j) {
        const uint8_t *p = keys + (j < count ? j : 0) * stride;
        low[j] = _mm_loadu_si128((const __m128i *)(const void *)p);
        high[j] = load_tail(p+16);
    }
    transpose_keys(words,low,high);
}

static void expand_rijndael(sydo_cipher_keys *expanded, const uint8_t *keys,
                             size_t stride, size_t lanes, __m128i rotate) {
    for (size_t first = 0; first < lanes; first += 4) {
        size_t count = lanes - first < 4 ? lanes - first : 4;
        __m128i words[SYDO_CIPHER_KEY_WORDS];
        load_keys(words,keys+first*stride,stride,count);
        store_round(expanded,first,count,0,words,SYDO_CIPHER_KEY_WORDS);
        uint8_t rcon = 1;
        for (unsigned r = 1; r <= SYDO_CIPHER_ROUNDS; ++r) {
            rijndael_expand_round(words,rotate,&rcon);
            store_round(expanded,first,count,r,words,SYDO_CIPHER_KEY_WORDS);
        }
        volatile __m128i *secret = words;
        for (unsigned w = 0; w < SYDO_CIPHER_KEY_WORDS; ++w) secret[w] = _mm_setzero_si128();
    }
}


void cipher_expand_shared(uint8_t *round_keys, size_t round_stride,
                            const uint8_t key[SYDO_CIPHER_KEY_BYTES], unsigned block_bytes) {
    uint32_t words[SYDO_CIPHER_KEY_WORDS];
    for (unsigned j = 0; j < SYDO_CIPHER_KEY_WORDS; ++j) words[j] = sydo_load32(key+4u*j);
    unsigned width = block_bytes/4u, count = (SYDO_CIPHER_ROUNDS+1u)*width;
    uint32_t rcon = 1;
    for (unsigned j = 0; j < count; ++j) {
        unsigned slot = j%SYDO_CIPHER_KEY_WORDS;
        if (j >= SYDO_CIPHER_KEY_WORDS) {
            uint32_t temp = words[(j-1u)%SYDO_CIPHER_KEY_WORDS];
            if (!slot) {
                temp = (temp >> 8)|(temp << 24);
                temp = (uint32_t)_mm_cvtsi128_si32(_mm_aesenclast_si128(_mm_set1_epi32((int)temp),_mm_setzero_si128()))^rcon;
                rcon = ((rcon << 1)^((0u-(rcon >> 7))&0x1bu))&255u;
            } else if (SYDO_CIPHER_KEY_WORDS > 6u && slot == 4u)
                temp = (uint32_t)_mm_cvtsi128_si32(_mm_aesenclast_si128(_mm_set1_epi32((int)temp),_mm_setzero_si128()));
            words[slot] ^= temp;
        }
        sydo_store32(round_keys+(j/width)*round_stride+4u*(j%width),words[slot]);
    }
    volatile uint32_t *secret = words;
    for (unsigned j = 0; j < SYDO_CIPHER_KEY_WORDS; ++j) secret[j] = 0;
}

static __attribute__((noinline)) void expand_aes(sydo_cipher_keys *expanded, const uint8_t *keys,
                                                  size_t stride, size_t lanes, __m128i rotate) {
    for (size_t first = 0; first < lanes; first += 4) {
        size_t count = lanes - first < 4 ? lanes - first : 4;
        __m128i words[(SYDO_CIPHER_ROUNDS+1u)*SYDO_MATRIX_BLOCK_BYTES/4u];
        load_keys(words,keys+first*stride,stride,count);
        unsigned total = (SYDO_CIPHER_ROUNDS+1u)*SYDO_MATRIX_BLOCK_BYTES/4u, width = SYDO_MATRIX_BLOCK_BYTES/4u, generated = SYDO_CIPHER_KEY_WORDS;
        uint8_t rcon = 1;
        while (generated < total) {
            __m128i temp = _mm_shuffle_epi8(_mm_aesenclast_si128(words[generated-1u],_mm_setzero_si128()),rotate);
            temp = _mm_xor_si128(temp,_mm_set1_epi32(rcon));
            rcon = (uint8_t)((rcon << 1)^((0u-(rcon >> 7))&0x1bu));
            for (unsigned slot = 0; slot < SYDO_CIPHER_KEY_WORDS && generated < total; ++slot,++generated) {
                if (SYDO_CIPHER_KEY_WORDS > 6u && slot == 4u) temp = substitute_word(temp);
                temp = _mm_xor_si128(words[generated-SYDO_CIPHER_KEY_WORDS],temp);
                words[generated] = temp;
            }
        }
        for (unsigned r = 0; r <= SYDO_CIPHER_ROUNDS; ++r) store_round(expanded,first,count,r,words+r*width,width);
        volatile __m128i *secret = words;
        for (unsigned w = 0; w < total; ++w) secret[w] = _mm_setzero_si128();
    }
}

void cipher_expand(sydo_cipher_keys *expanded, sydo_cipher_round_keys *workspace,
                    const uint8_t *keys,
                    size_t key_stride, size_t lanes, unsigned block_bytes) {
    expanded->keys = workspace;
    expanded->block_bytes = block_bytes;
    expanded->lanes = key_stride ? lanes : 1u;
    if (!key_stride) {
        cipher_expand_shared((uint8_t *)(void *)workspace,block_bytes,keys,block_bytes);
        return;
    }
    const __m128i rotate = _mm_loadu_si128((const __m128i *)(const void *)rotate_subword);
    if (block_bytes == SYDO_CIPHER_BLOCK_BYTES) { expand_rijndael(expanded,keys,key_stride,lanes,rotate); return; }
    expand_aes(expanded,keys,key_stride,lanes,rotate);
}

static void encrypt_aes(const sydo_cipher_keys *expanded, const uint8_t *input,
                        size_t input_stride, uint8_t *output,
                        size_t output_stride, size_t lanes) {
    for (size_t first = 0; first < lanes; first += 8) {
        size_t count = lanes - first < 8 ? lanes - first : 8;
        __m128i state[8];
        const uint8_t *keys[8];
        for (size_t j = 0; j < 8; ++j) {
            size_t lane = first + (j < count ? j : 0);
            keys[j] = (const uint8_t *)(const void *)expanded->keys+(expanded->lanes == 1 ? 0 : lane)*(SYDO_CIPHER_ROUNDS+1u)*SYDO_MATRIX_BLOCK_BYTES;
            state[j] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)(input + lane * input_stride)),
                                     _mm_loadu_si128((const __m128i *)(const void *)keys[j]));
        }
        for (unsigned r = 1; r < SYDO_CIPHER_ROUNDS; ++r) {
#pragma GCC unroll 8
            for (size_t j = 0; j < 8; ++j)
                state[j] = _mm_aesenc_si128(state[j], _mm_loadu_si128((const __m128i *)(const void *)(keys[j]+r*SYDO_MATRIX_BLOCK_BYTES)));
        }
        for (size_t j = 0; j < count; ++j) {
            state[j] = _mm_aesenclast_si128(state[j], _mm_loadu_si128((const __m128i *)(const void *)(keys[j]+SYDO_CIPHER_ROUNDS*SYDO_MATRIX_BLOCK_BYTES)));
            _mm_storeu_si128((__m128i *)(void *)(output + (first + j) * output_stride), state[j]);
        }
        volatile __m128i *secret = state;
        for (unsigned j = 0; j < 8; ++j) secret[j] = _mm_setzero_si128();
    }
}

static void encrypt_rijndael(const sydo_cipher_keys *expanded, const uint8_t *input,
                             size_t input_stride, uint8_t *output,
                             size_t output_stride, size_t lanes) {
    __m128i mask[3];
    for (unsigned i = 0; i < 3; ++i)
        mask[i] = _mm_loadu_si128((const __m128i *)(const void *)rijndael_rows[i]);
    for (size_t first = 0; first < lanes; first += 4) {
        size_t count = lanes - first < 4 ? lanes - first : 4;
        __m128i lo[4], hi[4];
        const sydo_cipher_round_keys *keys[4];
        for (size_t j = 0; j < 4; ++j) {
            size_t lane = first + (j < count ? j : 0);
            const uint8_t *p = input + lane * input_stride;
            keys[j] = expanded->keys + (expanded->lanes == 1 ? 0 : lane);
            const uint64_t *k = keys[j]->round[0];
            lo[j] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(const void *)p), _mm_loadu_si128((const __m128i *)(const void *)k));
            hi[j] = _mm_xor_si128(load_tail(p+16), load_tail((const uint8_t *)(const void *)(k+2)));
        }
        for (unsigned r = 1; r <= SYDO_CIPHER_ROUNDS; ++r) {
#pragma GCC unroll 4
            for (size_t j = 0; j < 4; ++j) {
                const uint64_t *key = keys[j]->round[r];
                __m128i kl = _mm_loadu_si128((const __m128i *)(const void *)key);
                __m128i kh = load_tail((const uint8_t *)(const void *)(key+2));
                rijndael_round(&lo[j], &hi[j], kl, kh, mask, r == SYDO_CIPHER_ROUNDS);
            }
        }
        for (size_t j = 0; j < count; ++j) {
            uint8_t *p = output + (first + j) * output_stride;
            _mm_storeu_si128((__m128i *)(void *)p, lo[j]);
            memcpy(p+16,&hi[j],SYDO_CIPHER_BLOCK_BYTES-16u);
        }
        volatile __m128i *secret_lo = lo, *secret_hi = hi;
        for (unsigned j = 0; j < 4; ++j) { secret_lo[j] = _mm_setzero_si128(); secret_hi[j] = _mm_setzero_si128(); }
    }
}

static inline void store_prefix(uint8_t *destination, __m128i low, __m128i high,
                                 size_t taken, uint8_t bytes[16], uint64_t *tail) {
    if (taken < 16u) {
        _mm_storeu_si128((__m128i *)(void *)bytes,low);
        memcpy(destination,bytes,taken);
        return;
    }
    _mm_storeu_si128((__m128i *)(void *)destination,low);
    destination += 16u;
    unsigned remaining = (unsigned)taken-16u;
    if (remaining == 16u) { _mm_storeu_si128((__m128i *)(void *)destination,high); return; }
    if (remaining >= 8u) {
        _mm_storel_epi64((__m128i *)(void *)destination,high);
        destination += 8u; remaining -= 8u;
        high = _mm_srli_si128(high,8);
    }
    *tail = (uint64_t)_mm_cvtsi128_si64(high);
    while (remaining >= 4u) {
        sydo_store32(destination,(uint32_t)*tail);
        destination += 4u; *tail >>= 32; remaining -= 4u;
    }
    for (unsigned j = 0; j < remaining; ++j) destination[j] = (uint8_t)(*tail >> (8u*j));
}

static inline __attribute__((always_inline)) void generate_pair_chunk(const sydo_prg_job *jobs, unsigned key_bytes, const uint8_t iv[SYDO_SEED_BYTES],
                     size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes, size_t first_block, size_t output_offset) {
    enum { max_states = 8 };
    __m128i mask[3];
    for (unsigned i = 0; i < 3; ++i) mask[i] = _mm_loadu_si128((const __m128i *)(const void *)rijndael_rows[i]);
    const __m128i rotate = _mm_loadu_si128((const __m128i *)(const void *)rotate_subword);
    size_t blocks = output_bytes > block_output_bytes ? 2u : 1u;
    uint64_t round_keys[4][SYDO_CIPHER_BLOCK_BYTES/8u];
    __m128i words[SYDO_CIPHER_KEY_WORDS], lo[max_states], hi[max_states];
    uint8_t bytes[16]; uint64_t tail = 0;
    for (size_t first = 0; first < lanes; first += 4) {
        size_t count = lanes-first < 4 ? lanes-first : 4;
        __m128i low[4], high[4];
        for (unsigned j = 0; j < 4; ++j) {
            const uint8_t *p = jobs[first+(j < count ? j : 0)].seed;
            low[j] = _mm_loadu_si128((const __m128i *)(const void *)p);
#if SYDO_CIPHER_KEY_WORDS == 6u
            high[j] = key_bytes == 20u ? _mm_cvtsi32_si128((int)sydo_load32(p+16)) : load_tail(p+16);
#else
            (void)key_bytes;
            high[j] = load_tail(p+16);
#endif
        }
        transpose_keys(words,low,high);
        store_words((uint8_t *)(void *)round_keys,sizeof(round_keys[0]),4,words,SYDO_CIPHER_KEY_WORDS);
        for (unsigned j = 0; j < 4; ++j) {
            size_t lane = first+(j < count ? j : 0);
            __m128i kl = _mm_loadu_si128((const __m128i *)(const void *)round_keys[j]);
            __m128i kh = load_tail((const uint8_t *)(const void *)(round_keys[j]+2));
            __m128i counter_high = counter_tail(iv,jobs[lane].tweak);
            for (size_t b = 0; b < blocks; ++b) {
                lo[4u*b+j] = _mm_xor_si128(_mm_add_epi32(_mm_loadu_si128((const __m128i *)(const void *)iv),_mm_set_epi32(0,0,0,(int)(uint32_t)(first_block+b))),kl);
                hi[4u*b+j] = _mm_xor_si128(counter_high,kh);
            }
        }
        uint8_t rcon = 1;
        for (unsigned r = 1; r <= SYDO_CIPHER_ROUNDS; ++r) {
            rijndael_expand_round(words,rotate,&rcon);
            store_words((uint8_t *)(void *)round_keys,sizeof(round_keys[0]),4,words,SYDO_CIPHER_KEY_WORDS);
            for (size_t b = 0; b < blocks; ++b) {
#pragma GCC unroll 4
                for (unsigned j = 0; j < 4; ++j) {
                    __m128i kl = _mm_loadu_si128((const __m128i *)(const void *)round_keys[j]);
                    __m128i kh = load_tail((const uint8_t *)(const void *)(round_keys[j]+2));
                    rijndael_round(&lo[4u*b+j],&hi[4u*b+j],kl,kh,mask,r == SYDO_CIPHER_ROUNDS);
                }
            }
        }
        for (size_t b = 0; b < blocks; ++b) {
            size_t offset = b*block_output_bytes;
            size_t taken = output_bytes-offset < block_output_bytes ? output_bytes-offset : block_output_bytes;
            for (unsigned j = 0; j < count; ++j)
                store_prefix(jobs[first+j].output+output_offset+offset,lo[4u*b+j],hi[4u*b+j],taken,bytes,&tail);
        }
    }
    volatile __m128i *sl = lo, *sh = hi, *sw = words;
    for (size_t j = 0; j < 4u*blocks; ++j) { sl[j] = _mm_setzero_si128(); sh[j] = _mm_setzero_si128(); }
    for (unsigned j = 0; j < SYDO_CIPHER_KEY_WORDS; ++j) sw[j] = _mm_setzero_si128();
    for (unsigned j = 0; j < 4; ++j) {
        volatile uint64_t *secret = round_keys[j];
        for (unsigned w = 0; w < SYDO_CIPHER_BLOCK_BYTES/8u; ++w) secret[w] = 0;
    }
    sydo_wipe(bytes,sizeof(bytes)); sydo_wipe(&tail,sizeof(tail));
}

void cipher_generate_pair_jobs(const sydo_prg_job *jobs, unsigned key_bytes,
                     const uint8_t iv[SYDO_SEED_BYTES], size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes) {
    if (!lanes || !output_bytes) return;
    size_t span = 2u*block_output_bytes;
    for (size_t offset = 0; offset < output_bytes; offset += span) {
        size_t taken = output_bytes-offset < span ? output_bytes-offset : span;
        generate_pair_chunk(jobs, key_bytes, iv, lanes, taken, block_output_bytes,
                            offset/block_output_bytes, offset);
    }
}

void cipher_generate_pair(const uint8_t *const *keys, unsigned key_bytes,
                     const uint8_t iv[SYDO_SEED_BYTES], const uint32_t *tweaks,
                     uint8_t *const *output, size_t lanes, size_t output_bytes, unsigned block_output_bytes) {
    if (!lanes || !output_bytes) return;
    for (size_t first = 0; first < lanes; first += 64u) {
        size_t count = lanes-first < 64u ? lanes-first : 64u;
        sydo_prg_job jobs[64];
        for (size_t j = 0; j < count; ++j)
            jobs[j] = (sydo_prg_job){keys[first+j], output[first+j], tweaks[first+j]};
        cipher_generate_pair_jobs(jobs, key_bytes, iv, count, output_bytes, block_output_bytes);
    }
}

static inline __attribute__((always_inline)) void encrypt_stream_blocks(
        __m128i low[4], __m128i high[4], const sydo_cipher_round_keys *key,
        const __m128i mask[3], unsigned count) {
    for (unsigned round = 1; round < SYDO_CIPHER_ROUNDS; ++round) {
        __m128i kl = _mm_loadu_si128((const __m128i *)(const void *)key->round[round]);
        __m128i kh = load_tail((const uint8_t *)(const void *)(key->round[round]+2));
#pragma GCC unroll 4
        for (unsigned j = 0; j < count; ++j) rijndael_round(&low[j],&high[j],kl,kh,mask,0);
    }
    __m128i kl = _mm_loadu_si128((const __m128i *)(const void *)key->round[SYDO_CIPHER_ROUNDS]);
    __m128i kh = load_tail((const uint8_t *)(const void *)(key->round[SYDO_CIPHER_ROUNDS]+2));
#pragma GCC unroll 4
    for (unsigned j = 0; j < count; ++j) rijndael_round(&low[j],&high[j],kl,kh,mask,1);
}

void cipher_generate_stream_jobs(const sydo_cipher_keys *expanded, const uint8_t iv[SYDO_SEED_BYTES],
                     const sydo_prg_job *jobs, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes) {
    if (!lanes || !output_bytes) return;
    __m128i mask[3], lo[4], hi[4];
    uint8_t bytes[16]; uint64_t tail = 0;
    for (unsigned i = 0; i < 3; ++i) mask[i] = _mm_loadu_si128((const __m128i *)(const void *)rijndael_rows[i]);
    const __m128i initial = _mm_loadu_si128((const __m128i *)(const void *)iv);
    size_t blocks = (output_bytes+block_output_bytes-1u)/block_output_bytes;
    for (size_t lane = 0; lane < lanes; ++lane) {
        const sydo_cipher_round_keys *key = expanded->keys+(expanded->lanes == 1 ? 0 : lane);
        __m128i counter_high = counter_tail(iv,jobs[lane].tweak);
        for (size_t first = 0; first < blocks; first += 4) {
            unsigned count = (unsigned)(blocks-first < 4 ? blocks-first : 4);
            __m128i kl = _mm_loadu_si128((const __m128i *)(const void *)key->round[0]);
            __m128i kh = load_tail((const uint8_t *)(const void *)(key->round[0]+2));
            for (unsigned j = 0; j < count; ++j) {
                lo[j] = _mm_xor_si128(_mm_add_epi32(initial,_mm_set_epi32(0,0,0,(int)(first+j))),kl);
                hi[j] = _mm_xor_si128(counter_high,kh);
            }
            switch (count) {
                case 4: encrypt_stream_blocks(lo,hi,key,mask,4); break;
                case 3: encrypt_stream_blocks(lo,hi,key,mask,3); break;
                case 2: encrypt_stream_blocks(lo,hi,key,mask,2); break;
                default: encrypt_stream_blocks(lo,hi,key,mask,1); break;
            }
            for (unsigned j = 0; j < count; ++j) {
                size_t offset = (first+j)*block_output_bytes;
                size_t taken = output_bytes-offset < block_output_bytes ? output_bytes-offset : block_output_bytes;
                store_prefix(jobs[lane].output+offset,lo[j],hi[j],taken,bytes,&tail);
            }
        }
    }
    volatile __m128i *sl = lo, *sh = hi;
    for (unsigned j = 0; j < 4; ++j) { sl[j] = _mm_setzero_si128(); sh[j] = _mm_setzero_si128(); }
    sydo_wipe(bytes,sizeof(bytes)); sydo_wipe(&tail,sizeof(tail));
}

void cipher_generate_stream(const sydo_cipher_keys *expanded, const uint8_t iv[SYDO_SEED_BYTES],
                     const uint32_t *tweaks, uint8_t *const *output, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes) {
    if (!lanes || !output_bytes) return;
    for (size_t first = 0; first < lanes; first += 64u) {
        size_t count = lanes-first < 64u ? lanes-first : 64u;
        sydo_prg_job jobs[64];
        for (size_t j = 0; j < count; ++j)
            jobs[j] = (sydo_prg_job){NULL, output[first+j], tweaks[first+j]};
        sydo_cipher_keys part = *expanded;
        if (part.lanes != 1u) { part.keys += first; part.lanes = count; }
        cipher_generate_stream_jobs(&part, iv, jobs, count, output_bytes, block_output_bytes);
    }
}


void cipher_encrypt(const sydo_cipher_keys *expanded, const uint8_t *input,
                     size_t input_stride, uint8_t *output,
                     size_t output_stride, size_t lanes) {
    if (expanded->block_bytes == 16) encrypt_aes(expanded, input, input_stride, output, output_stride, lanes);
    else encrypt_rijndael(expanded, input, input_stride, output, output_stride, lanes);
}

void cipher_clear(sydo_cipher_keys *expanded) {
    volatile uint64_t *words = (volatile uint64_t *)(void *)expanded->keys;
    size_t count = expanded->lanes*sizeof(*expanded->keys)/sizeof(*words);
    for (size_t i = 0; i < count; ++i) words[i] = 0;
    expanded->block_bytes = 0;
    expanded->lanes = 0;
}
