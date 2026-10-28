#include "sydo.h"
#include "keygen.h"
#include "parameters.h"
#include "bytes.h"
#include "cipher.h"
#include "hash.h"
#include <string.h>

size_t sydo_public_key_bytes(void) { return SYDO_PK_BYTES; }
size_t sydo_secret_key_bytes(void) { return SYDO_SK_BYTES; }
size_t sydo_signature_bytes(void) { return SYDO_SIG_BYTES; }

static unsigned reverse_byte(unsigned x) {
    unsigned y = 0;
    for (unsigned b = 0; b < SYDO_RSD_ETA_1; ++b) y |= ((x >> b) & 1u) << (SYDO_RSD_ETA_1 - 1u - b);
    return y;
}

static unsigned weight(unsigned x) {
    unsigned n = 0;
    for (unsigned b = 0; b < SYDO_RSD_ETA_1; ++b) n += (x >> b) & 1u;
    return n;
}

static void ball_elements(uint8_t ball[SYDO_RSD_BALL_TERMS]) {
    unsigned rank = 0;
    for (unsigned w = 0; w <= SYDO_RSD_R_1; ++w)
        for (unsigned v = 0; v < SYDO_RSD_MASK_COUNT; ++v)
            if (weight(v) == w) ball[rank++] = (uint8_t)reverse_byte(v);
}

/* RSD.ExpandWitness: graded lexicographic Hamming balls H(2,1), H(8,3).
 * All table traversals use public indices; secret ranks are mask-selected. */
static void witness_encode(uint8_t witness[SYDO_WITNESS_BYTES],
                            const uint16_t positions[SYDO_RSD_WEIGHT]) {
    uint8_t ball[SYDO_RSD_BALL_TERMS];
    ball_elements(ball);
    memset(witness, 0, SYDO_WITNESS_BYTES);
    for (unsigned i = 0; i < SYDO_RSD_WEIGHT; ++i) {
        unsigned a = positions[i] / SYDO_RSD_BALL_TERMS, b = positions[i] % SYDO_RSD_BALL_TERMS;
        unsigned encoding = (2u & sydo_equal32(a, 1)) | (1u & sydo_equal32(a, 2));
        for (unsigned j = 0; j < SYDO_RSD_BALL_TERMS; ++j) encoding |= (unsigned)(ball[j] << 2) & sydo_equal32(b, j);
        for (unsigned j = 0; j < SYDO_RSD_INPUT_BITS; ++j)
            witness[(SYDO_RSD_INPUT_BITS * i + j) / 8] |= (uint8_t)(((encoding >> j) & 1u) << ((SYDO_RSD_INPUT_BITS * i + j) % 8));
    }
}

static int witness_sample(uint16_t positions[SYDO_RSD_WEIGHT], const uint8_t seed[SYDO_SEED_BYTES]) {
    uint8_t input[SYDO_SEED_BYTES + 5], block[32];
    uint64_t counter = 0;
    const uint64_t limit = ((UINT64_C(1) << 32) / SYDO_RSD_BLOCK_LENGTH) * SYDO_RSD_BLOCK_LENGTH;
    unsigned accepted = 0;
    memcpy(input, seed, SYDO_SEED_BYTES);
    input[SYDO_SEED_BYTES + 4] = 0x58;
    while (accepted < SYDO_RSD_WEIGHT) {
        if (counter == (UINT64_C(1) << 32)) {
            sydo_wipe(input, sizeof(input));
            return -1;
        }
        sydo_store32(input + SYDO_SEED_BYTES, (uint32_t)counter++);
        if (sydo_xof(block, sizeof(block), input, sizeof(input))) {
            sydo_wipe(input, sizeof(input));
            sydo_wipe(block, sizeof(block));
            return -1;
        }
        for (unsigned j = 0; j < 8 && accepted < SYDO_RSD_WEIGHT; ++j) {
            uint32_t candidate = sydo_load32(block + 4 * j);
            /* Rejection count is independent of the accepted uniform position. */
            if ((uint64_t)candidate < limit)
                positions[accepted++] = (uint16_t)(candidate % SYDO_RSD_BLOCK_LENGTH);
        }
    }
    sydo_wipe(input, sizeof(input));
    sydo_wipe(block, sizeof(block));
    return 0;
}

static __attribute__((noinline)) void syndrome(uint8_t output[SYDO_SYNDROME_BYTES], const uint8_t matrix_seed[SYDO_SEED_BYTES],
                       const uint16_t positions[SYDO_RSD_WEIGHT]) {
    sydo_cipher_keys schedule;
    sydo_cipher_round_keys round_keys;
    uint8_t key[SYDO_CIPHER_KEY_BYTES] = {0}, input[SYDO_CIPHER_SHARED_LANES][SYDO_MATRIX_BLOCK_BYTES], blocks[SYDO_CIPHER_SHARED_LANES][SYDO_MATRIX_BLOCK_BYTES];
    memcpy(key, matrix_seed, SYDO_SEED_BYTES);
    cipher_expand(&schedule, &round_keys, key, 0, SYDO_CIPHER_SHARED_LANES, SYDO_MATRIX_BLOCK_BYTES);
    memset(output, 0, SYDO_SYNDROME_BYTES);
    const unsigned blocks_per_element = (SYDO_SEED_BYTES + SYDO_MATRIX_BLOCK_BYTES - 1u) / SYDO_MATRIX_BLOCK_BYTES;
    const unsigned total = SYDO_SYNDROME_FIELDS * SYDO_RSD_WEIGHT, batch = SYDO_CIPHER_SHARED_LANES / blocks_per_element;
    for (unsigned first = 0; first < total; first += batch) {
        unsigned items = total - first < batch ? total - first : batch;
        memset(input, 0, sizeof(input));
        for (unsigned j = 0; j < items; ++j) {
            unsigned index = first + j;
            uint32_t column = (index % SYDO_RSD_WEIGHT) * SYDO_RSD_BLOCK_LENGTH + positions[index % SYDO_RSD_WEIGHT];
            uint32_t element = (index / SYDO_RSD_WEIGHT) * SYDO_RSD_COLUMNS + column;
            for (unsigned b = 0; b < blocks_per_element; ++b)
                sydo_store32(input[blocks_per_element * j + b], blocks_per_element * element + b);
        }
        cipher_encrypt(&schedule, input[0], SYDO_MATRIX_BLOCK_BYTES, blocks[0], SYDO_MATRIX_BLOCK_BYTES, blocks_per_element * items);
        for (unsigned j = 0; j < items; ++j) {
            unsigned row = (first + j) / SYDO_RSD_WEIGHT;
            for (unsigned k = 0; k < SYDO_SEED_BYTES && SYDO_SEED_BYTES * row + k < SYDO_SYNDROME_BYTES; ++k) output[SYDO_SEED_BYTES * row + k] ^= blocks[blocks_per_element * j + k / SYDO_MATRIX_BLOCK_BYTES][k % SYDO_MATRIX_BLOCK_BYTES];
        }
    }
    cipher_clear(&schedule);
    sydo_wipe(input, sizeof(input));
    sydo_wipe(blocks, sizeof(blocks));
    sydo_wipe(key, sizeof(key));
}

/* Preserve the value while hiding its range from subsequent optimization.
 * Otherwise a compiler can turn rank selection into secret-dependent branches. */
static inline unsigned sydo_rank_value_barrier(unsigned value) {
#if (defined(__GNUC__) || defined(__clang__)) && !defined(SYDO_RANK_FORCE_C_FALLBACK)
    __asm__("" : "+r"(value));
    return value;
#else
    volatile unsigned stored = value;
    return stored;
#endif
}

int sydo_validate_secret_key(const uint8_t sk[SYDO_SK_BYTES]) {
    uint8_t ball[SYDO_RSD_BALL_TERMS], computed[SYDO_SYNDROME_BYTES];
    uint16_t positions[SYDO_RSD_WEIGHT];
    const uint8_t *witness = sk + SYDO_SK_WITNESS_OFFSET;
    unsigned invalid = 0;
    ball_elements(ball);
    for (unsigned row = 0; row < SYDO_RSD_WEIGHT; ++row) {
        unsigned first = SYDO_RSD_INPUT_BITS * row;
        unsigned low = sydo_bit(witness, first), high = sydo_bit(witness, first + 1u);
        unsigned value = 0, rank = 0, found = 0;
        for (unsigned bit = 0; bit < SYDO_RSD_ETA_1; ++bit)
            value |= sydo_bit(witness, first + SYDO_RSD_ETA_0 + bit) << bit;
        for (unsigned j = 0; j < SYDO_RSD_BALL_TERMS; ++j) {
            unsigned equal = sydo_rank_value_barrier(sydo_equal32(value, ball[j]));
            rank |= j & equal;
            found |= equal;
        }
        invalid |= (low & high) | (found ^ UINT32_MAX);
        positions[row] = (uint16_t)((2u * low + high) * SYDO_RSD_BALL_TERMS + rank);
    }
#if (SYDO_RSD_INPUT_BITS * SYDO_RSD_WEIGHT) % 8u
    invalid |= witness[SYDO_WITNESS_BYTES - 1u] >> ((SYDO_RSD_INPUT_BITS * SYDO_RSD_WEIGHT) % 8u);
#endif
    syndrome(computed, sk, positions);
    invalid |= sydo_difference(computed, sk + SYDO_SEED_BYTES, sizeof(computed));
    sydo_wipe(positions, sizeof(positions));
    sydo_wipe(computed, sizeof(computed));
    return -(int)((invalid | (0u - invalid)) >> 31);
}

int sydo_keygen_from_seed(uint8_t *pk, size_t pk_capacity,
                          uint8_t *sk, size_t sk_capacity,
                          const uint8_t *entropy, size_t entropy_bytes) {
    uint16_t positions[SYDO_RSD_WEIGHT];
    if (!pk || !sk || !entropy || pk_capacity < SYDO_PK_BYTES ||
        sk_capacity < SYDO_SK_BYTES || entropy_bytes != SYDO_KEYGEN_SEED_BYTES)
        return -1;
    int status = witness_sample(positions, entropy);
    if (!status) {
        memcpy(pk, entropy + SYDO_SEED_BYTES, SYDO_SEED_BYTES);
        syndrome(pk + SYDO_SEED_BYTES, pk, positions);
        memcpy(sk, pk, SYDO_PK_BYTES);
        memcpy(sk + SYDO_PK_BYTES, entropy, SYDO_SEED_BYTES);
        witness_encode(sk + SYDO_PK_BYTES + SYDO_SEED_BYTES, positions);
    }
    sydo_wipe(positions, sizeof(positions));
    return status;
}
