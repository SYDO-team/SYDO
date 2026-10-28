#include "cipher.h"
#include "bytes.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef SYDO_CIPHER_BLAKE2S
#include "blake2s.h"
static uint32_t rotate_word(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u-count));
}
static void encrypt(uint8_t *out, const uint8_t *in, const uint8_t key[SYDO_CIPHER_KEY_BYTES], unsigned bytes) {
    (void)bytes;
    uint32_t state[16], message[16];
    static const unsigned coordinates[8][4] = {
        {0,4,8,12},{1,5,9,13},{2,6,10,14},{3,7,11,15},
        {0,5,10,15},{1,6,11,12},{2,7,8,13},{3,4,9,14}
    };
    for (unsigned j = 0; j < 16; ++j) { state[j] = sydo_load32(in+4u*j); message[j] = sydo_load32(key+4u*j); }
    for (unsigned round = 0; round < 10; ++round)
        for (unsigned group = 0; group < 8; ++group) {
            uint32_t q[4];
            for (unsigned j = 0; j < 4; ++j) q[j] = state[coordinates[group][j]];
            for (unsigned half = 0; half < 2; ++half) {
                q[0] = q[0] + q[1] + message[blake2s_sigma[round][2u*group+half]];
                q[3] = rotate_word(q[3]^q[0], half ? 8u : 16u);
                q[2] += q[3];
                q[1] = rotate_word(q[1]^q[2], half ? 7u : 12u);
            }
            for (unsigned j = 0; j < 4; ++j) state[coordinates[group][j]] = q[j];
        }
    for (unsigned j = 0; j < 16; ++j) sydo_store32(out+4u*j,state[j]);
}
#else
static uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (b & 1u) result ^= a;
        a = (uint8_t)((a << 1) ^ ((a >> 7) ? 0x1bu : 0));
        b >>= 1;
    }
    return result;
}

static uint8_t substitute(uint8_t a) {
    uint8_t inverse = 1;
    for (unsigned i = 0; i < 8; ++i) {
        if ((254u >> i) & 1u) inverse = multiply(inverse, a);
        a = multiply(a, a);
    }
    uint8_t result = inverse ^ 0x63u;
    for (unsigned i = 1; i <= 4; ++i)
        result ^= (uint8_t)((inverse << i) | (inverse >> (8 - i)));
    return result;
}

static void encrypt(uint8_t *out, const uint8_t *in, const uint8_t key[SYDO_CIPHER_KEY_BYTES], unsigned bytes) {
    uint8_t expanded[(SYDO_CIPHER_ROUNDS+1u)*SYDO_CIPHER_BLOCK_BYTES], state[SYDO_CIPHER_BLOCK_BYTES], rcon = 1;
    memcpy(expanded, key, SYDO_CIPHER_KEY_BYTES);
    for (unsigned first = SYDO_CIPHER_KEY_BYTES; first < (SYDO_CIPHER_ROUNDS+1u) * bytes; first += 4) {
        uint8_t temp[4];
        memcpy(temp, expanded + first - 4, 4);
        if (first % SYDO_CIPHER_KEY_BYTES == 0) {
            uint8_t saved = temp[0];
            for (unsigned j = 0; j < 3; ++j) temp[j] = substitute(temp[j + 1]);
            temp[3] = substitute(saved);
            temp[0] ^= rcon;
            rcon = multiply(rcon, 2);
        }
        if (SYDO_CIPHER_KEY_WORDS > 6u && first % SYDO_CIPHER_KEY_BYTES == 16u)
            for (unsigned j = 0; j < 4; ++j) temp[j] = substitute(temp[j]);
        for (unsigned j = 0; j < 4; ++j) expanded[first + j] = expanded[first - SYDO_CIPHER_KEY_BYTES + j] ^ temp[j];
    }
    for (unsigned i = 0; i < bytes; ++i) state[i] = in[i] ^ expanded[i];
    for (unsigned round = 1; round <= SYDO_CIPHER_ROUNDS; ++round) {
        uint8_t next[SYDO_CIPHER_BLOCK_BYTES];
        for (unsigned column = 0; column < bytes / 4; ++column)
            for (unsigned row = 0; row < 4; ++row)
                next[4 * column + row] = substitute(state[4 * ((column + row + (bytes == 32u && row >= 2u)) % (bytes / 4)) + row]);
        for (unsigned column = 0; column < bytes / 4; ++column) {
            const uint8_t *x = next + 4 * column;
            for (unsigned row = 0; row < 4; ++row) {
                uint8_t value = x[row];
                if (round != SYDO_CIPHER_ROUNDS)
                    value = multiply(x[row], 2) ^ multiply(x[(row + 1) % 4], 3) ^ x[(row + 2) % 4] ^ x[(row + 3) % 4];
                state[4 * column + row] = value ^ expanded[round * bytes + 4 * column + row];
            }
        }
    }
    memcpy(out, state, bytes);
}

#endif

#if defined(SYDO_AVX2) && defined(SYDO_CIPHER_BLAKE2S)
static int matrix_counters(void) {
    uint8_t key[64], output[33][66], input[64], expected[64];
    for (unsigned i = 0; i < 64; ++i) key[i] = (uint8_t)(17u*i+23u);
    const unsigned counts[] = {0,1,7,8,9,17,33};
    const uint32_t starts[] = {0,1,UINT32_MAX-3u};
    for (unsigned a = 0; a < sizeof(starts)/sizeof(starts[0]); ++a)
        for (unsigned b = 0; b < sizeof(counts)/sizeof(counts[0]); ++b) {
            memset(output,0xa5,sizeof(output));
            blake2s_matrix_blocks(output[0]+1,sizeof(output[0]),key,starts[a],counts[b]);
            for (unsigned lane = 0; lane < 33; ++lane) {
                if (lane < counts[b]) {
                    memset(input,0,sizeof(input));sydo_store32(input,starts[a]+lane);
                    encrypt(expected,input,key,64);
                    if (memcmp(output[lane]+1,expected,64)) return 1;
                }
                for (unsigned byte = 0; byte < 66; ++byte)
                    if ((lane >= counts[b] || byte == 0 || byte == 65) && output[lane][byte] != 0xa5) return 1;
            }
        }
    puts("Matrix cipher counters: direct oracle, partial batches, wraparound and guards verified");
    return 0;
}
#endif

#ifdef SYDO_AVX2
static int counter_streams(void) {
    enum { capacity = 17u*SYDO_CIPHER_BLOCK_BYTES };
    uint8_t keys[64][SYDO_CIPHER_KEY_BYTES], iv[SYDO_SEED_BYTES];
    uint8_t outputs[64][capacity+4u], reference[64][capacity];
    sydo_cipher_round_keys round_keys[64];
    sydo_cipher_keys expanded;
    sydo_prg_job jobs[64];
    const unsigned counts[] = {0,1,2,3,4,7,8,9,15,16,17,31,32,33,63,64};
    const unsigned widths[] = {SYDO_VOLE_BLOCK_OUTPUT_BYTES,SYDO_SEED_BYTES,SYDO_CIPHER_BLOCK_BYTES};
    memset(iv,255,sizeof(iv));
    for (unsigned lane = 0; lane < 64; ++lane) {
        for (unsigned j = 0; j < SYDO_CIPHER_KEY_BYTES; ++j) keys[lane][j] = (uint8_t)(lane*37u+j*13u);
        jobs[lane] = (sydo_prg_job){keys[lane],outputs[lane]+2u,UINT32_MAX-lane};
    }
    for (unsigned shared = 0; shared < 2; ++shared)
    for (unsigned w = 0; w < sizeof(widths)/sizeof(widths[0]); ++w) {
        unsigned width = widths[w];
        for (unsigned lane = 0; lane < 64; ++lane) jobs[lane].seed = keys[shared ? 0 : lane];
        if (w && width == widths[w-1u]) continue;
        for (unsigned lane = 0; lane < 64; ++lane)
            for (unsigned b = 0; b < 17u; ++b) {
                uint8_t input[SYDO_CIPHER_BLOCK_BYTES] = {0}, block[SYDO_CIPHER_BLOCK_BYTES];
                memcpy(input,iv,sizeof(iv));
                sydo_store32(input,sydo_load32(iv)+b);
                sydo_store32(input+SYDO_SEED_BYTES-4u,sydo_load32(iv+SYDO_SEED_BYTES-4u)+jobs[lane].tweak);
                encrypt(block,input,keys[shared ? 0 : lane],SYDO_CIPHER_BLOCK_BYTES);
                memcpy(reference[lane]+b*width,block,width);
            }
        for (unsigned c = 0; c < sizeof(counts)/sizeof(counts[0]); ++c) {
            unsigned lanes = counts[c];
            unsigned lengths[] = {0,1,7u*width,7u*width+1u,8u*width-1u,8u*width,8u*width+1u,
                                  9u*width+1u,15u*width+1u,16u*width,16u*width+1u,17u*width};
            cipher_expand(&expanded,round_keys,keys[0],shared ? 0 : SYDO_CIPHER_KEY_BYTES,lanes,SYDO_CIPHER_BLOCK_BYTES);
            for (unsigned n = 0; n < sizeof(lengths)/sizeof(lengths[0]); ++n) {
                unsigned length = lengths[n];
                for (unsigned method = 0; method < 2; ++method) {
                memset(outputs,0xa5,sizeof(outputs));
                if (method) cipher_generate_pair_jobs(jobs,SYDO_CIPHER_KEY_BYTES,iv,lanes,length,width);
                else cipher_generate_stream_jobs(&expanded,iv,jobs,lanes,length,width);
                for (unsigned lane = 0; lane < 64; ++lane) {
                    if (lane < lanes && memcmp(outputs[lane]+2u,reference[lane],length)) return 1;
                    for (unsigned j = 0; j < sizeof(outputs[0]); ++j)
                        if ((lane >= lanes || j < 2u || j >= length+2u) && outputs[lane][j] != 0xa5) return 1;
                }
                }
            }
            cipher_clear(&expanded);
        }
    }
    puts("Cipher stream jobs: shared keys, counter groups, wraparound, truncation and guards verified");
    return 0;
}
#endif

int main(void) {
    const unsigned counts[] = {1, 2, 7, 8, 9, 31, 32, 33, 63, 64};
    uint8_t keys[64][SYDO_CIPHER_KEY_BYTES], input[64][SYDO_CIPHER_BLOCK_BYTES], output[64][SYDO_CIPHER_BLOCK_BYTES], expected[SYDO_CIPHER_BLOCK_BYTES];
    sydo_cipher_keys schedule;
    sydo_cipher_round_keys round_keys[SYDO_CIPHER_BATCH_KEYS];
    for (unsigned lane = 0; lane < 64; ++lane)
        for (unsigned j = 0; j < SYDO_CIPHER_KEY_BYTES; ++j) {
            keys[lane][j] = (uint8_t)(17 * lane + 3 * j);
            input[lane][j] = (uint8_t)(7 * lane + 11 * j);
        }
    for (unsigned bytes = SYDO_MATRIX_BLOCK_BYTES; bytes <= SYDO_CIPHER_BLOCK_BYTES; bytes += SYDO_CIPHER_BLOCK_BYTES == SYDO_MATRIX_BLOCK_BYTES ? 1u : SYDO_CIPHER_BLOCK_BYTES - SYDO_MATRIX_BLOCK_BYTES)
        for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c)
            for (unsigned shared = 0; shared < 2; ++shared) {
                unsigned lanes = counts[c];
                cipher_expand(&schedule, round_keys, keys[0], shared ? 0 : SYDO_CIPHER_KEY_BYTES, lanes, bytes);
                cipher_encrypt(&schedule, input[0], SYDO_CIPHER_BLOCK_BYTES, output[0], SYDO_CIPHER_BLOCK_BYTES, lanes);
                for (unsigned lane = 0; lane < lanes; ++lane) {
                    encrypt(expected, input[lane], keys[shared ? 0 : lane], bytes);
                    if (memcmp(expected, output[lane], bytes)) { fprintf(stderr, "cipher mismatch: bytes=%u lanes=%u lane=%u shared=%u\n", bytes, lanes, lane, shared); return 1; }
                }
                cipher_encrypt(&schedule, input[0], 0, output[0], SYDO_CIPHER_BLOCK_BYTES, lanes);
                for (unsigned lane = 0; lane < lanes; ++lane) {
                    encrypt(expected, input[0], keys[shared ? 0 : lane], bytes);
                    if (memcmp(expected, output[lane], bytes)) return 1;
                }
                cipher_clear(&schedule);
            }
    uint8_t spaced_keys[64][SYDO_CIPHER_KEY_BYTES+7u];
    memset(spaced_keys,0xa5,sizeof(spaced_keys));
    for (unsigned lane = 0; lane < 64; ++lane) memcpy(spaced_keys[lane],keys[lane],SYDO_CIPHER_KEY_BYTES);
    for (unsigned c = 0; c < sizeof(counts)/sizeof(counts[0]); ++c) {
        unsigned lanes = counts[c];
        cipher_expand(&schedule,round_keys,spaced_keys[0],sizeof(spaced_keys[0]),lanes,SYDO_CIPHER_BLOCK_BYTES);
        memset(output,0xa5,sizeof(output));
        cipher_encrypt(&schedule,input[0],SYDO_CIPHER_BLOCK_BYTES,output[0],SYDO_CIPHER_BLOCK_BYTES,lanes);
        for (unsigned lane = 0; lane < 64; ++lane) {
            if (lane < lanes) {
                encrypt(expected,input[lane],keys[lane],SYDO_CIPHER_BLOCK_BYTES);
                if (memcmp(expected,output[lane],sizeof(expected))) return 1;
            } else for (unsigned j = 0; j < sizeof(output[0]); ++j) if (output[lane][j] != 0xa5) return 1;
            for (unsigned j = SYDO_CIPHER_KEY_BYTES; j < sizeof(spaced_keys[0]); ++j) if (spaced_keys[lane][j] != 0xa5) return 1;
        }
        cipher_clear(&schedule);
    }
#ifdef SYDO_AVX2
    uint8_t iv[SYDO_SEED_BYTES], streams[64][5u*SYDO_CIPHER_BLOCK_BYTES], *destinations[64], plaintext[SYDO_CIPHER_BLOCK_BYTES];
    uint32_t tweaks[64];
    const uint8_t *key_pointers[64];
    memset(iv,255,sizeof(iv));
    for (unsigned lane = 0; lane < 64; ++lane) {
        destinations[lane] = streams[lane]; key_pointers[lane] = keys[lane]; tweaks[lane] = UINT32_MAX-lane;
    }
    uint8_t reference[64][5u*SYDO_CIPHER_BLOCK_BYTES];
    const unsigned key_sizes[] = {SYDO_SEED_BYTES,SYDO_CIPHER_KEY_BYTES};
    const unsigned widths[] = {SYDO_MATRIX_BLOCK_BYTES,SYDO_SEED_BYTES,SYDO_CIPHER_BLOCK_BYTES};
    for (unsigned k = 0; k < sizeof(key_sizes)/sizeof(key_sizes[0]); ++k)
    for (unsigned w = 0; w < sizeof(widths)/sizeof(widths[0]); ++w) {
        unsigned key_bytes = key_sizes[k], width = widths[w];
        for (unsigned lane = 0; lane < 64; ++lane)
            for (unsigned block = 0; block < 5; ++block) {
                memset(plaintext,0,sizeof(plaintext)); memcpy(plaintext,iv,sizeof(iv));
                sydo_store32(plaintext,sydo_load32(iv)+block);
                sydo_store32(plaintext+SYDO_SEED_BYTES-4u,sydo_load32(iv+SYDO_SEED_BYTES-4u)+tweaks[lane]);
                uint8_t padded_key[SYDO_CIPHER_KEY_BYTES] = {0}; memcpy(padded_key,keys[lane],key_bytes);
                encrypt(expected,plaintext,padded_key,SYDO_CIPHER_BLOCK_BYTES);
                memcpy(reference[lane]+block*width,expected,width);
            }
        for (unsigned c = 0; c < sizeof(counts)/sizeof(counts[0]); ++c) {
            unsigned lengths[] = {0,1,width,width+1u,2u*width,2u*width+1u,3u*width,5u*width};
            for (unsigned n = 0; n < sizeof(lengths)/sizeof(lengths[0]); ++n) {
                unsigned length = lengths[n], lanes = counts[c];
                memset(streams,0xa5,sizeof(streams));
                cipher_generate_pair(key_pointers,key_bytes,iv,tweaks,destinations,lanes,length,width);
                for (unsigned lane = 0; lane < lanes; ++lane) if (memcmp(reference[lane],streams[lane],length)) return 1;
                for (unsigned lane = 0; lane < 64; ++lane)
                    for (unsigned offset = lane < lanes ? length : 0; offset < sizeof(streams[0]); ++offset)
                        if (streams[lane][offset] != 0xa5) return 1;
            }
        }
    }
    uint8_t long_output[64][SYDO_VOLE_BYTES+4u], long_reference[64][SYDO_VOLE_BYTES];
    const unsigned blocks = (SYDO_VOLE_BYTES+SYDO_VOLE_BLOCK_OUTPUT_BYTES-1u)/SYDO_VOLE_BLOCK_OUTPUT_BYTES;
    for (unsigned lane = 0; lane < 64; ++lane) {
        destinations[lane] = long_output[lane]+2u;
        for (unsigned b = 0; b < blocks; ++b) {
            memset(plaintext,0,sizeof(plaintext)); memcpy(plaintext,iv,sizeof(iv));
            sydo_store32(plaintext,sydo_load32(iv)+b);
            sydo_store32(plaintext+SYDO_SEED_BYTES-4u,sydo_load32(iv+SYDO_SEED_BYTES-4u)+tweaks[lane]);
            encrypt(expected,plaintext,keys[lane],SYDO_CIPHER_BLOCK_BYTES);
            unsigned offset = b*SYDO_VOLE_BLOCK_OUTPUT_BYTES;
            unsigned taken = SYDO_VOLE_BYTES-offset < SYDO_VOLE_BLOCK_OUTPUT_BYTES ? SYDO_VOLE_BYTES-offset : SYDO_VOLE_BLOCK_OUTPUT_BYTES;
            memcpy(long_reference[lane]+offset,expected,taken);
        }
    }
    for (unsigned c = 0; c < sizeof(counts)/sizeof(counts[0]); ++c) {
        unsigned lanes = counts[c];
        cipher_expand(&schedule,round_keys,keys[0],SYDO_CIPHER_KEY_BYTES,lanes,SYDO_CIPHER_BLOCK_BYTES);
        memset(long_output,0xa5,sizeof(long_output));
        cipher_generate_stream(&schedule,iv,tweaks,destinations,lanes,SYDO_VOLE_BYTES,SYDO_VOLE_BLOCK_OUTPUT_BYTES);
        for (unsigned lane = 0; lane < 64; ++lane) {
            if (lane < lanes && memcmp(long_output[lane]+2u,long_reference[lane],SYDO_VOLE_BYTES)) return 1;
            for (unsigned j = 0; j < sizeof(long_output[0]); ++j)
                if ((lane >= lanes || j < 2u || j >= SYDO_VOLE_BYTES+2u) && long_output[lane][j] != 0xa5) return 1;
        }
        cipher_clear(&schedule);
    }
    if (counter_streams()) return 1;
    puts("Cipher counter streams: truncation, partial batches, wraparound and guard bytes verified");

#endif
#if defined(SYDO_AVX2) && defined(SYDO_CIPHER_BLAKE2S)
    if (matrix_counters()) return 1;
#endif
    puts("Cipher: distinct keys/inputs, shared keys/inputs and partial batches verified");
    return 0;
}
