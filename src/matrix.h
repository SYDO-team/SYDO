#ifndef SYDO_MATRIX_H
#define SYDO_MATRIX_H

#include "fields.h"

/* Matrix entries and challenge multipliers are public. */
typedef struct {
#ifdef SYDO_CIPHER_BLAKE2S
    uint8_t key[SYDO_CIPHER_KEY_BYTES];
#ifdef SYDO_AVX2
    sydo_field alpha[SYDO_SYNDROME_FIELDS];
#else
    sydo_field multiples[SYDO_SYNDROME_FIELDS][2 * SYDO_SEED_BYTES][16];
#endif
#elif defined(SYDO_AVX2)
    uint8_t round_keys[(SYDO_CIPHER_ROUNDS + 1u) * SYDO_MATRIX_BLOCK_BYTES];
    sydo_field alpha[SYDO_SYNDROME_FIELDS];
#else
    uint32_t round_keys[(SYDO_CIPHER_ROUNDS + 1) * SYDO_MATRIX_BLOCK_BYTES / 4];
    uint32_t table[4][256];
    uint8_t sbox[256];
    sydo_field multiples[SYDO_SYNDROME_FIELDS][2 * SYDO_SEED_BYTES][16];
#endif
} sydo_public_matrix;

void matrix_init(sydo_public_matrix *matrix, const uint8_t seed[SYDO_SEED_BYTES], const sydo_field alpha[SYDO_SYNDROME_FIELDS]);
void matrix_fold_row(sydo_field folded[SYDO_RSD_BLOCK_LENGTH], const sydo_public_matrix *matrix,
                       unsigned row);

#endif
