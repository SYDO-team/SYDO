#include "cipher.h"
#include "blake2s.h"
#include "bytes.h"
#include <string.h>

static inline uint32_t rotate(uint32_t x, unsigned bits) {
    return (x >> bits) | (x << (32u - bits));
}

static void encrypt_block(uint8_t out[64], const uint8_t in[64], const uint8_t key[64]) {
    uint32_t state[16], message[16];
    for (unsigned i = 0; i < 16; ++i) {
        state[i] = sydo_load32(in + 4u*i);
        message[i] = sydo_load32(key + 4u*i);
    }
    for (unsigned round = 0; round < 10; ++round) {
#pragma GCC unroll 8
        for (unsigned group = 0; group < 8; ++group) {
            unsigned a = group % 4u, diagonal = group / 4u;
            unsigned b = 4u + (a + diagonal) % 4u;
            unsigned c = 8u + (a + 2u*diagonal) % 4u;
            unsigned d = 12u + (a + 3u*diagonal) % 4u;
            state[a] += state[b] + message[blake2s_sigma[round][2u*group]];
            state[d] = rotate(state[d] ^ state[a], 16);
            state[c] += state[d];
            state[b] = rotate(state[b] ^ state[c], 12);
            state[a] += state[b] + message[blake2s_sigma[round][2u*group+1u]];
            state[d] = rotate(state[d] ^ state[a], 8);
            state[c] += state[d];
            state[b] = rotate(state[b] ^ state[c], 7);
        }
    }
    for (unsigned i = 0; i < 16; ++i) sydo_store32(out + 4u*i, state[i]);
    sydo_wipe(state, sizeof(state));
    sydo_wipe(message, sizeof(message));
}

void cipher_encrypt(const sydo_cipher_keys *expanded, const uint8_t *input,
                     size_t input_stride, uint8_t *output, size_t output_stride, size_t lanes) {
    for (size_t i = 0; i < lanes; ++i)
        encrypt_block(output + i*output_stride, input + i*input_stride,
                      expanded->keys[expanded->lanes == 1u ? 0 : i].key);
}

