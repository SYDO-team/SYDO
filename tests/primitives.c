#include "cipher.h"
#include "fields.h"
#include "bytes.h"
#include <stdio.h>
#include <string.h>

static sydo_field multiply_bits(sydo_field a, sydo_field b) {
    sydo_field c = field_zero();
    for (unsigned bit = 0; bit < SYDO_LAMBDA; ++bit) {
        c = field_add(c, field_mask(a, (unsigned)((b.word[bit / 64] >> (bit % 64)) & 1u)));
        a = field_shift(a);
    }
    return c;
}

int main(void) {
#ifndef SYDO_CIPHER_BLAKE2S
#if SYDO_CIPHER_KEY_BYTES == 24u
    static const uint8_t ciphertext[16] = {
        0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
    };
#else
    static const uint8_t ciphertext[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };
#endif
    uint8_t key[SYDO_CIPHER_KEY_BYTES], input[64][16], output[64][16];
    sydo_cipher_keys schedule;
    sydo_cipher_round_keys round_keys[SYDO_CIPHER_BATCH_KEYS];
    for (unsigned i = 0; i < SYDO_CIPHER_KEY_BYTES; ++i) key[i] = (uint8_t)i;
    for (unsigned i = 0; i < 64; ++i)
        for (unsigned j = 0; j < 16; ++j) input[i][j] = (uint8_t)(17 * j);
    cipher_expand(&schedule, round_keys, key, 0, 64, 16);
    cipher_encrypt(&schedule, input[0], 16, output[0], 16, 64);
    for (unsigned i = 0; i < 64; ++i)
        if (memcmp(output[i], ciphertext, 16)) { fprintf(stderr, "AES vector failed at lane %u\n", i); return 1; }
    cipher_clear(&schedule);
#else
    static const uint8_t expected_block[64] = {
        0x8f,0xcb,0x2e,0x96,0x0a,0xd5,0x87,0x0e,0x40,0xe2,0x74,0xf1,0xed,0x78,0xe2,0xef,
        0xc0,0x94,0xe3,0x72,0x84,0xcb,0x6d,0x2b,0x5d,0x54,0xa4,0xca,0x31,0xb0,0x12,0x39,
        0xc8,0x57,0x34,0x89,0x3e,0x17,0xbd,0xdc,0x53,0xf0,0x3e,0xac,0x95,0xc2,0xd3,0x99,
        0x60,0x50,0x13,0xbf,0xc2,0x7c,0xce,0xe8,0x7e,0x3b,0xf8,0xdb,0x12,0x36,0xe2,0xea
    };
    uint8_t key[64], input[64][64], output[64][64];
    sydo_cipher_keys schedule;
    sydo_cipher_round_keys keys[SYDO_CIPHER_BATCH_KEYS];
    for (unsigned i = 0; i < 64; ++i) key[i] = (uint8_t)i;
    for (unsigned lane = 0; lane < 64; ++lane)
        for (unsigned i = 0; i < 64; ++i) input[lane][i] = (uint8_t)(17u*i);
    cipher_expand(&schedule, keys, key, 0, 64, 64);
    cipher_encrypt(&schedule, input[0], 64, output[0], 64, 64);
    for (unsigned lane = 0; lane < 64; ++lane)
        if (memcmp(output[lane], expected_block, sizeof(expected_block))) return 1;
    cipher_clear(&schedule);
    puts("BLAKE2s internal block: 64 lanes match fixed vector");
#endif
    uint64_t state = UINT64_C(0xd861a7395b2ce40f);
    for (unsigned i = 0; i < 256; ++i) {
        sydo_field a = field_zero(), b = field_zero();
        for (unsigned w = 0; w < SYDO_FIELD_WORDS; ++w) {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17; a.word[w] = state;
            state ^= state << 13; state ^= state >> 7; state ^= state << 17; b.word[w] = state;
        }
#if SYDO_LAMBDA % 64u
        a.word[SYDO_FIELD_WORDS - 1u] &= (UINT64_C(1) << (SYDO_LAMBDA % 64u)) - 1u;
        b.word[SYDO_FIELD_WORDS - 1u] &= (UINT64_C(1) << (SYDO_LAMBDA % 64u)) - 1u;
#endif
        sydo_field expected = multiply_bits(a, b), actual = field_mul(a, b);
        if (memcmp(&expected, &actual, sizeof(actual))) { fprintf(stderr, "field product failed at %u\n", i); return 1; }
        for (unsigned w = 1; w < SYDO_FIELD_WORDS; ++w) b.word[w] = 0;
        expected = multiply_bits(a, b); actual = field_mul64(a, b.word[0]);
        if (memcmp(&expected, &actual, sizeof(actual))) { fprintf(stderr, "field by 64-bit product failed at %u\n", i); return 1; }
    }
    printf("Cipher key %u bits: GF(2^%u): 256 products match bit-polynomial oracle\n", 8u*SYDO_CIPHER_KEY_BYTES, (unsigned)SYDO_LAMBDA);
    return 0;
}
