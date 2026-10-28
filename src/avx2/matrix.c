#include "matrix.h"
#include "cipher.h"
#include "bytes.h"
#include "profile.h"
#include <immintrin.h>
#include <string.h>

void matrix_init(sydo_public_matrix *matrix, const uint8_t seed[SYDO_SEED_BYTES], const sydo_field alpha[SYDO_SYNDROME_FIELDS]) {
    uint8_t key[SYDO_CIPHER_KEY_BYTES] = {0};
    memcpy(key,seed,SYDO_SEED_BYTES);
    cipher_expand_shared(matrix->round_keys,SYDO_MATRIX_BLOCK_BYTES,key,SYDO_MATRIX_BLOCK_BYTES);
    sydo_wipe(key,sizeof(key));
    memcpy(matrix->alpha, alpha, sizeof(matrix->alpha));
}

void matrix_fold_row(sydo_field folded[SYDO_RSD_BLOCK_LENGTH], const sydo_public_matrix *matrix, unsigned row) {
    enum { batch = 8 };
    for (unsigned first = 0; first < SYDO_RSD_BLOCK_LENGTH; first += batch) {
        unsigned count = SYDO_RSD_BLOCK_LENGTH - first < batch ? SYDO_RSD_BLOCK_LENGTH - first : batch;
        sydo_field_product sums[batch];
        for (unsigned j = 0; j < count; ++j) sums[j] = field_product_zero();
        for (unsigned block = 0; block < SYDO_SYNDROME_FIELDS; ++block) {
            __m128i state[2 * batch];
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_EXPAND);
            __m128i k0 = _mm_loadu_si128((const __m128i *)(const void *)matrix->round_keys);
            for (unsigned j = 0; j < 2 * batch; ++j) {
                uint32_t index = block * SYDO_RSD_COLUMNS + row * SYDO_RSD_BLOCK_LENGTH + first + (j / 2 < count ? j / 2 : 0);
                state[j] = _mm_xor_si128(_mm_set_epi32(0, 0, 0, (int)(2 * index + j % 2)), k0);
            }
            for (unsigned r = 1; r < SYDO_CIPHER_ROUNDS; ++r) {
                __m128i key = _mm_loadu_si128((const __m128i *)(const void *)(matrix->round_keys + r * SYDO_MATRIX_BLOCK_BYTES));
#pragma GCC unroll 16
                for (unsigned j = 0; j < 2 * batch; ++j) state[j] = _mm_aesenc_si128(state[j], key);
            }
            __m128i last = _mm_loadu_si128((const __m128i *)(const void *)(matrix->round_keys + SYDO_CIPHER_ROUNDS * SYDO_MATRIX_BLOCK_BYTES));
            for (unsigned j = 0; j < 2 * batch; ++j) state[j] = _mm_aesenclast_si128(state[j], last);
            SYDO_PROFILE_END(PROFILE_MATRIX_EXPAND);
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_FOLD);
            for (unsigned j = 0; j < count; ++j) {
                uint8_t bytes[32];
                _mm_storeu_si128((__m128i *)(void *)bytes, state[2 * j]);
                _mm_storeu_si128((__m128i *)(void *)(bytes + 16), state[2 * j + 1]);
                sums[j] = field_product_add(sums[j], field_product_mul(field_read(bytes), matrix->alpha[block]));
            }
            SYDO_PROFILE_END(PROFILE_MATRIX_FOLD);
        }
        SYDO_PROFILE_BEGIN(PROFILE_MATRIX_FOLD);
        for (unsigned j = 0; j < count; ++j) folded[first+j] = field_product_reduce(sums[j]);
        SYDO_PROFILE_END(PROFILE_MATRIX_FOLD);
    }
}
