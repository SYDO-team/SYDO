#include "profile.h"
#include "matrix.h"
#include "bytes.h"
#include <string.h>

static unsigned byte_product(unsigned a, unsigned b) {
    unsigned result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        result ^= a & (0u - (b & 1u));
        a = ((a << 1) ^ ((0u - (a >> 7)) & 0x11bu)) & 255u;
        b >>= 1;
    }
    return result;
}

static unsigned sbox_value(unsigned x) {
    unsigned inverse = 1;
    for (unsigned p = 0; p < 8; ++p) {
        if ((254u >> p) & 1u) inverse = byte_product(inverse, x);
        x = byte_product(x, x);
    }
    unsigned output = inverse ^ 0x63u;
    for (unsigned shift = 1; shift <= 4; ++shift)
        output ^= ((inverse << shift) | (inverse >> (8 - shift))) & 255u;
    return output;
}

static uint32_t substitute_word(const sydo_public_matrix *matrix, uint32_t word) {
    uint32_t result = 0;
    for (unsigned j = 0; j < 4; ++j) result |= (uint32_t)matrix->sbox[(word >> (8u*j)) & 255u] << (8u*j);
    return result;
}

void matrix_init(sydo_public_matrix *matrix, const uint8_t seed[SYDO_SEED_BYTES], const sydo_field alpha[SYDO_SYNDROME_FIELDS]) {
    for (unsigned i = 0; i < 256; ++i) {
        unsigned s = sbox_value(i), twice = byte_product(s, 2);
        matrix->sbox[i] = (uint8_t)s;
        uint32_t column = (uint32_t)twice | (uint32_t)s << 8 | (uint32_t)s << 16 | (uint32_t)(twice ^ s) << 24;
        for (unsigned row = 0; row < 4; ++row)
            matrix->table[row][i] = row ? (column << (8 * row)) | (column >> (32 - 8 * row)) : column;
    }
    uint8_t key[SYDO_CIPHER_KEY_BYTES] = {0};
    memcpy(key, seed, SYDO_SEED_BYTES);
    for (unsigned i = 0; i < SYDO_CIPHER_KEY_WORDS; ++i) matrix->round_keys[i] = sydo_load32(key + 4 * i);
    unsigned rcon = 1;
    for (unsigned i = SYDO_CIPHER_KEY_WORDS; i < (SYDO_CIPHER_ROUNDS + 1) * SYDO_MATRIX_BLOCK_BYTES / 4; ++i) {
        uint32_t temp = matrix->round_keys[i - 1];
        if (i % SYDO_CIPHER_KEY_WORDS == 0) {
            temp = (temp >> 8) | (temp << 24);
            temp = substitute_word(matrix, temp) ^ rcon;
            rcon = byte_product(rcon, 2);
        }
        if (SYDO_CIPHER_KEY_WORDS > 6u && i % SYDO_CIPHER_KEY_WORDS == 4u) temp = substitute_word(matrix, temp);
        matrix->round_keys[i] = matrix->round_keys[i - SYDO_CIPHER_KEY_WORDS] ^ temp;
    }
    /* Both the challenge multipliers and matrix entries are public. */
    for (unsigned block = 0; block < SYDO_SYNDROME_FIELDS; ++block) {
        sydo_field power = alpha[block];
        for (unsigned digit = 0; digit < 2 * SYDO_SEED_BYTES; ++digit) {
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
}

static void encrypt_counter(uint8_t output[16], const sydo_public_matrix *matrix, uint32_t counter) {
    uint32_t state[4] = {counter, 0, 0, 0};
    for (unsigned c = 0; c < 4; ++c) state[c] ^= matrix->round_keys[c];
    for (unsigned r = 1; r < SYDO_CIPHER_ROUNDS; ++r) {
        uint32_t next[4];
        for (unsigned c = 0; c < 4; ++c) {
            next[c] = matrix->round_keys[4 * r + c];
            for (unsigned row = 0; row < 4; ++row)
                next[c] ^= matrix->table[row][(state[(c + row) % 4] >> (8 * row)) & 255];
        }
        memcpy(state, next, sizeof(state));
    }
    for (unsigned c = 0; c < 4; ++c) {
        uint32_t word = matrix->round_keys[4 * SYDO_CIPHER_ROUNDS + c];
        for (unsigned row = 0; row < 4; ++row)
            word ^= (uint32_t)matrix->sbox[(state[(c + row) % 4] >> (8 * row)) & 255] << (8 * row);
        sydo_store32(output + 4 * c, word);
    }
}

void matrix_fold_row(sydo_field folded[SYDO_RSD_BLOCK_LENGTH], const sydo_public_matrix *matrix,
                       unsigned row) {
    for (unsigned column = 0; column < SYDO_RSD_BLOCK_LENGTH; ++column) {
        folded[column] = field_zero();
        for (unsigned block = 0; block < SYDO_SYNDROME_FIELDS; ++block) {
            uint8_t bytes[32];
            uint32_t index = block * SYDO_RSD_COLUMNS + row * SYDO_RSD_BLOCK_LENGTH + column;
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_EXPAND);
            encrypt_counter(bytes, matrix, 2 * index);
            encrypt_counter(bytes + 16, matrix, 2 * index + 1);
            SYDO_PROFILE_END(PROFILE_MATRIX_EXPAND);
            SYDO_PROFILE_BEGIN(PROFILE_MATRIX_FOLD);
            for (unsigned digit = 0; digit < 2 * SYDO_SEED_BYTES; ++digit)
                folded[column] = field_add(folded[column],
                    matrix->multiples[block][digit][(bytes[digit / 2] >> (4 * (digit % 2))) & 15u]);
            SYDO_PROFILE_END(PROFILE_MATRIX_FOLD);
        }
    }
}
