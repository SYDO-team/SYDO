#include "matrix.h"
#include "cipher.h"
#include "blake2s.h"
#include "bytes.h"
#include "profile.h"
#include <string.h>

void matrix_init(sydo_public_matrix *matrix, const uint8_t seed[SYDO_SEED_BYTES],
                    const sydo_field alpha[SYDO_SYNDROME_FIELDS]) {
    memcpy(matrix->key, seed, SYDO_CIPHER_KEY_BYTES);
#ifdef SYDO_AVX2
    memcpy(matrix->alpha, alpha, sizeof(matrix->alpha));
#else
    for (unsigned block = 0; block < SYDO_SYNDROME_FIELDS; ++block) {
        sydo_field power = alpha[block];
        for (unsigned digit = 0; digit < 2u*SYDO_SEED_BYTES; ++digit) {
            sydo_field basis[4];
            for (unsigned bit = 0; bit < 4; ++bit) { basis[bit] = power; power = field_shift(power); }
            matrix->multiples[block][digit][0] = field_zero();
            for (unsigned value = 1; value < 16; ++value) {
                unsigned bit = 0;
                while (!(value & (1u << bit))) ++bit;
                matrix->multiples[block][digit][value] =
                    field_add(matrix->multiples[block][digit][value ^ (1u << bit)], basis[bit]);
            }
        }
    }
#endif
}

void matrix_fold_row(sydo_field folded[SYDO_RSD_BLOCK_LENGTH], const sydo_public_matrix *matrix, unsigned row) {
#ifdef SYDO_AVX2
    enum { batch = 8 };
    for (unsigned first = 0; first < SYDO_RSD_BLOCK_LENGTH; first += batch) {
        unsigned count = SYDO_RSD_BLOCK_LENGTH - first < batch ? SYDO_RSD_BLOCK_LENGTH - first : batch;
        sydo_field_product sums[batch];
        for (unsigned j = 0; j < count; ++j) sums[j] = field_product_zero();
        for (unsigned block = 0; block < SYDO_SYNDROME_FIELDS; ++block) {
            uint8_t output[batch][SYDO_CIPHER_BLOCK_BYTES];
            uint32_t counter = block * SYDO_RSD_COLUMNS + row * SYDO_RSD_BLOCK_LENGTH + first;
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_EXPAND);
            blake2s_matrix_blocks(output[0],SYDO_CIPHER_BLOCK_BYTES,matrix->key,counter,count);
            SYDO_PROFILE_END(PROFILE_MATRIX_EXPAND);
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_FOLD);
            for (unsigned j = 0; j < count; ++j) {
                size_t remaining = SYDO_SYNDROME_BYTES - block * SYDO_SEED_BYTES;
                if (remaining < SYDO_SEED_BYTES) memset(output[j] + remaining, 0, SYDO_SEED_BYTES - remaining);
                sums[j] = field_product_add(sums[j], field_product_mul(field_read(output[j]), matrix->alpha[block]));
            }
            SYDO_PROFILE_END(PROFILE_MATRIX_FOLD);
        }
        for (unsigned j = 0; j < count; ++j) folded[first+j] = field_product_reduce(sums[j]);
    }
#else
    sydo_cipher_keys schedule;
    sydo_cipher_round_keys key;
    cipher_expand(&schedule, &key, matrix->key, 0, 1, SYDO_CIPHER_BLOCK_BYTES);
    for (unsigned column = 0; column < SYDO_RSD_BLOCK_LENGTH; ++column) {
        folded[column] = field_zero();
        for (unsigned block = 0; block < SYDO_SYNDROME_FIELDS; ++block) {
            uint8_t input[SYDO_CIPHER_BLOCK_BYTES] = {0}, output[SYDO_CIPHER_BLOCK_BYTES];
            sydo_store32(input, block * SYDO_RSD_COLUMNS + row * SYDO_RSD_BLOCK_LENGTH + column);
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_EXPAND);
            cipher_encrypt(&schedule, input, 0, output, 0, 1);
            SYDO_PROFILE_END(PROFILE_MATRIX_EXPAND);
            size_t remaining = SYDO_SYNDROME_BYTES - block * SYDO_SEED_BYTES;
            if (remaining < SYDO_SEED_BYTES) memset(output + remaining, 0, SYDO_SEED_BYTES - remaining);
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_FOLD);
            for (unsigned digit = 0; digit < 2u*SYDO_SEED_BYTES; ++digit)
                folded[column] = field_add(folded[column], matrix->multiples[block][digit][(output[digit/2u] >> (4u*(digit%2u))) & 15u]);
            SYDO_PROFILE_END(PROFILE_MATRIX_FOLD);
        }
    }
    cipher_clear(&schedule);
#endif
}
