#include "cipher.h"
#include "bytes.h"
#include <string.h>

typedef sydo_cipher_byte byte;

static void clear_bytes(byte *bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        volatile uint64_t *bits = bytes[i].bits;
        for (unsigned j = 0; j < 8; ++j) bits[j] = 0;
    }
}

void cipher_clear(sydo_cipher_keys *expanded) {
    for (unsigned round = 0; round <= SYDO_CIPHER_ROUNDS; ++round) clear_bytes(expanded->keys->round[round], SYDO_CIPHER_BLOCK_BYTES);
    expanded->block_bytes = 0;
    expanded->lanes = 0;
}

static void pack_bytes(byte *output, unsigned bytes, const uint8_t *input,
                        size_t stride, size_t lanes) {
    if (!stride) {
        uint64_t mask = lanes == 64 ? UINT64_MAX : (UINT64_C(1) << lanes) - 1;
        for (unsigned j = 0; j < bytes; ++j)
            for (unsigned bit = 0; bit < 8; ++bit)
                output[j].bits[bit] = (UINT64_C(0) - ((input[j] >> bit) & 1u)) & mask;
        return;
    }
    const uint64_t masks[6] = {UINT64_C(0x5555555555555555), UINT64_C(0x3333333333333333),
        UINT64_C(0x0f0f0f0f0f0f0f0f), UINT64_C(0x00ff00ff00ff00ff),
        UINT64_C(0x0000ffff0000ffff), UINT64_C(0x00000000ffffffff)};
    uint64_t rows[64];
    for (unsigned offset = 0; offset < bytes; offset += 8) {
        for (unsigned lane = 0; lane < 64; ++lane) {
            if (lane < lanes) {
                const uint8_t *p = input + lane * stride + offset;
                rows[lane] = (uint64_t)sydo_load32(p) | ((uint64_t)sydo_load32(p + 4) << 32);
            } else rows[lane] = 0;
        }
        for (unsigned stage = 0; stage < 6; ++stage) {
            unsigned width = 1u << stage;
            for (unsigned group = 0; group < 64; group += 2 * width)
                for (unsigned j = 0; j < width; ++j) {
                    unsigned lo = group+j, hi = lo+width;
                    uint64_t changed = ((rows[lo] >> width) ^ rows[hi]) & masks[stage];
                    rows[lo] ^= changed << width;
                    rows[hi] ^= changed;
                }
        }
        for (unsigned j = 0; j < 8; ++j)
            for (unsigned bit = 0; bit < 8; ++bit) output[offset+j].bits[bit] = rows[8*j+bit];
    }
    volatile uint64_t *secret = rows;
    for (unsigned j = 0; j < 64; ++j) secret[j] = 0;
}

static void unpack_byte(uint8_t *output, size_t stride, size_t lanes, byte packed) {
    for (size_t first = 0; first < lanes; first += 8) {
        uint64_t x = 0;
        for (unsigned bit = 0; bit < 8; ++bit)
            x |= ((packed.bits[bit] >> first) & 255u) << (8 * bit);
        x = sydo_transpose8(x);
        for (unsigned j = 0; j < 8 && first + j < lanes; ++j)
            output[(first + j) * stride] = (uint8_t)(x >> (8 * j));
    }
}

static inline byte byte_xor(byte x, byte y) {
    for (unsigned bit = 0; bit < 8; ++bit) x.bits[bit] ^= y.bits[bit];
    return x;
}

static inline byte byte_xtime(byte x) {
    byte y;
    for (unsigned bit = 0; bit < 8; ++bit)
        y.bits[bit] = (bit ? x.bits[bit - 1] : 0) ^
                      (x.bits[7] & (UINT64_C(0) - ((0x1bu >> bit) & 1u)));
    return y;
}

typedef struct { uint64_t c[4]; } nibble;

/* GF(4) = GF(2)[Z]/(Z^2+Z+1), GF(16) = GF(4)[U]/(U^2+U+Z). */
static inline nibble nibble_mul(nibble a, nibble b) {
    uint64_t p0 = a.c[0] & b.c[0], p1 = a.c[1] & b.c[1];
    uint64_t p2 = (a.c[0] ^ a.c[1]) & (b.c[0] ^ b.c[1]);
    uint64_t q0 = a.c[2] & b.c[2], q1 = a.c[3] & b.c[3];
    uint64_t q2 = (a.c[2] ^ a.c[3]) & (b.c[2] ^ b.c[3]);
    uint64_t r0 = (a.c[0] ^ a.c[2]) & (b.c[0] ^ b.c[2]);
    uint64_t r1 = (a.c[1] ^ a.c[3]) & (b.c[1] ^ b.c[3]);
    uint64_t r2 = (a.c[0] ^ a.c[1] ^ a.c[2] ^ a.c[3]) &
                  (b.c[0] ^ b.c[1] ^ b.c[2] ^ b.c[3]);
    uint64_t low0 = p0 ^ p1, low1 = p2 ^ p0;
    uint64_t high0 = q0 ^ q1, high1 = q2 ^ q0;
    nibble result = {{low0 ^ high1, low1 ^ high0 ^ high1,
                       r0 ^ r1 ^ low0, r2 ^ r0 ^ low1}};
    return result;
}

static inline nibble nibble_inverse(nibble a) {
    uint64_t p0 = a.c[0] & a.c[2], p1 = a.c[1] & a.c[3];
    uint64_t p2 = (a.c[0] ^ a.c[1]) & (a.c[2] ^ a.c[3]);
    uint64_t norm0 = a.c[0] ^ a.c[1] ^ p0 ^ p1 ^ a.c[3];
    uint64_t norm1 = a.c[1] ^ p2 ^ p0 ^ a.c[2];
    uint64_t inv0 = norm0 ^ norm1, inv1 = norm1;
    uint64_t b0 = a.c[2] & inv0, b1 = a.c[3] & inv1;
    uint64_t b2 = (a.c[2] ^ a.c[3]) & (inv0 ^ inv1);
    uint64_t c0 = (a.c[0] ^ a.c[2]) & inv0;
    uint64_t c1 = (a.c[1] ^ a.c[3]) & inv1;
    uint64_t c2 = (a.c[0] ^ a.c[1] ^ a.c[2] ^ a.c[3]) & (inv0 ^ inv1);
    nibble result = {{c0 ^ c1, c2 ^ c0, b0 ^ b1, b2 ^ b0}};
    return result;
}

static inline byte byte_sbox(byte x) {
    /* Relative normal basis (T,T+1), with T^2+T=ZU.
     * Z, U and T map to 0xbd, 0xe1 and 0xa2 respectively. */
    byte mapped;
    uint64_t in0 = x.bits[3] ^ x.bits[4];
    uint64_t in1 = x.bits[1] ^ x.bits[2];
    uint64_t in2 = x.bits[5] ^ x.bits[7];
    uint64_t in3 = x.bits[6] ^ in0;
    uint64_t in4 = x.bits[7] ^ in1;
    mapped.bits[0] = x.bits[0] ^ x.bits[7];
    mapped.bits[1] = x.bits[4] ^ x.bits[6] ^ in4;
    mapped.bits[2] = in4;
    mapped.bits[3] = in0 ^ in2;
    mapped.bits[4] = x.bits[0] ^ x.bits[2] ^ in3;
    mapped.bits[5] = x.bits[2];
    mapped.bits[6] = in2 ^ in3;
    mapped.bits[7] = in0;
    nibble a, b;
    for (unsigned i = 0; i < 4; ++i) { a.c[i] = mapped.bits[i]; b.c[i] = mapped.bits[i + 4]; }
    nibble sum, ab = nibble_mul(a, b), norm;
    for (unsigned i = 0; i < 4; ++i) sum.c[i] = a.c[i] ^ b.c[i];
    uint64_t shared = sum.c[2] ^ sum.c[3];
    norm.c[0] = ab.c[0] ^ sum.c[2];
    norm.c[1] = ab.c[1] ^ shared;
    norm.c[2] = ab.c[2] ^ sum.c[1] ^ shared;
    norm.c[3] = ab.c[3] ^ sum.c[0] ^ sum.c[3];
    nibble inverse = nibble_inverse(norm), saved = a;
    a = nibble_mul(b, inverse); b = nibble_mul(saved, inverse);
    for (unsigned i = 0; i < 4; ++i) { mapped.bits[i] = a.c[i]; mapped.bits[i + 4] = b.c[i]; }
    byte result;
    uint64_t out0 = mapped.bits[0] ^ mapped.bits[7];
    uint64_t out1 = mapped.bits[2] ^ mapped.bits[5];
    uint64_t out2 = mapped.bits[1] ^ mapped.bits[4];
    uint64_t out3 = mapped.bits[6] ^ out1;
    result.bits[0] = out2 ^ out3 ^ UINT64_MAX;
    result.bits[1] = out0 ^ out3 ^ UINT64_MAX;
    result.bits[2] = mapped.bits[4] ^ mapped.bits[7] ^ out1;
    result.bits[3] = mapped.bits[5] ^ out2;
    result.bits[4] = mapped.bits[2] ^ out0;
    result.bits[5] = mapped.bits[2] ^ mapped.bits[3] ^ UINT64_MAX;
    result.bits[6] = mapped.bits[3] ^ mapped.bits[4] ^ out0 ^ UINT64_MAX;
    result.bits[7] = mapped.bits[6];
    return result;
}

static void substitute_pair(byte *word) {
    uint64_t input[8][2], output[8][2];
    for (unsigned bit = 0; bit < 8; ++bit)
        for (unsigned j = 0; j < 2; ++j) input[bit][j] = word[j].bits[bit];
    for (unsigned j = 0; j < 2; ++j) {
        byte x;
        for (unsigned bit = 0; bit < 8; ++bit) x.bits[bit] = input[bit][j];
        byte y = byte_sbox(x);
        for (unsigned bit = 0; bit < 8; ++bit) output[bit][j] = y.bits[bit];
    }
    for (unsigned bit = 0; bit < 8; ++bit)
        for (unsigned j = 0; j < 2; ++j) word[j].bits[bit] = output[bit][j];
}

void cipher_expand(sydo_cipher_keys *restrict expanded, sydo_cipher_round_keys *restrict workspace,
                    const uint8_t *restrict keys,
                    size_t key_stride, size_t lanes, unsigned block_bytes) {
    byte words[SYDO_CIPHER_KEY_WORDS][4], temp[4];
    uint8_t rcon = 1;
    unsigned count = (SYDO_CIPHER_ROUNDS + 1u) * block_bytes / 4;
    unsigned output_round = 0, output_column = 0;
    byte packed[SYDO_CIPHER_KEY_BYTES];
    pack_bytes(packed, SYDO_CIPHER_KEY_BYTES, keys, key_stride, lanes);
    for (unsigned offset = 0; offset < SYDO_CIPHER_KEY_BYTES; ++offset) {
        words[offset/4][offset%4] = packed[offset];
        workspace->round[output_round][output_column] = packed[offset];
        if (++output_column == block_bytes) { output_column = 0; ++output_round; }
    }
    clear_bytes(packed, SYDO_CIPHER_KEY_BYTES);
    unsigned generated = SYDO_CIPHER_KEY_WORDS;
    while (generated < count) {
        for (unsigned j = 0; j < 4; ++j) temp[j] = words[SYDO_CIPHER_KEY_WORDS - 1u][(j + 1) % 4];
        substitute_pair(temp);
        substitute_pair(temp + 2);
        for (unsigned bit = 0; bit < 8; ++bit)
            temp[0].bits[bit] ^= UINT64_C(0) - ((rcon >> bit) & 1u);
        rcon = (uint8_t)((rcon << 1) ^ ((0u - (rcon >> 7)) & 0x1bu));
        for (unsigned slot = 0; slot < SYDO_CIPHER_KEY_WORDS && generated < count; ++slot, ++generated) {
            if (SYDO_CIPHER_KEY_WORDS > 6u && slot == 4u) {
                substitute_pair(temp);
                substitute_pair(temp + 2);
            }
            for (unsigned j = 0; j < 4; ++j) {
                words[slot][j] = byte_xor(words[slot][j], temp[j]);
                workspace->round[output_round][output_column + j] = words[slot][j];
                temp[j] = words[slot][j];
            }
            output_column += 4;
            if (output_column == block_bytes) { output_column = 0; ++output_round; }
        }
    }
    for (unsigned w = 0; w < SYDO_CIPHER_KEY_WORDS; ++w) clear_bytes(words[w], 4);
    clear_bytes(temp, 4);
    expanded->keys = workspace;
    expanded->lanes = lanes;
    expanded->block_bytes = block_bytes;
}

void cipher_encrypt(const sydo_cipher_keys *expanded, const uint8_t *input,
                     size_t input_stride, uint8_t *output,
                     size_t output_stride, size_t lanes) {
    byte state[SYDO_CIPHER_BLOCK_BYTES] = {{{0}}}, shifted[SYDO_CIPHER_BLOCK_BYTES];
    unsigned n = expanded->block_bytes;
    pack_bytes(state, n, input, input_stride, lanes);
    for (unsigned j = 0; j < n; ++j) state[j] = byte_xor(state[j], expanded->keys->round[0][j]);
    for (unsigned round = 1; round <= SYDO_CIPHER_ROUNDS; ++round) {
        for (unsigned j = 0; j < n; j += 2) substitute_pair(state + j);
        for (unsigned row = 0; row < 4; ++row) {
            unsigned source = row + (n == 32u && row >= 2u);
            for (unsigned col = 0; col < n / 4; ++col) {
                shifted[4 * col + row] = state[4 * source + row];
                if (++source == n / 4) source = 0;
            }
        }
        for (unsigned col = 0; col < n / 4; ++col) {
            byte *s = shifted + 4 * col;
            byte total = byte_xor(byte_xor(s[0], s[1]), byte_xor(s[2], s[3]));
            for (unsigned row = 0; row < 4; ++row) {
                byte value = s[row];
                if (round != SYDO_CIPHER_ROUNDS)
                    value = byte_xor(value, byte_xor(total, byte_xtime(byte_xor(s[row], s[(row + 1) % 4]))));
                state[4 * col + row] = byte_xor(value, expanded->keys->round[round][4 * col + row]);
            }
        }
    }
    for (unsigned j = 0; j < n; ++j) unpack_byte(output + j, output_stride, lanes, state[j]);
    clear_bytes(shifted, SYDO_CIPHER_BLOCK_BYTES);
    clear_bytes(state, SYDO_CIPHER_BLOCK_BYTES);
}
