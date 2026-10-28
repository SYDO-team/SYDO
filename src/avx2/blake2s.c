#include "cipher.h"
#include "blake2s.h"
#include "bytes.h"
#include <immintrin.h>
#include <string.h>

static inline __m256i rotate(__m256i value, unsigned bits) {
    if (bits == 16u)
        return _mm256_shuffle_epi8(value,_mm256_setr_epi32(0x01000302,0x05040706,0x09080b0a,0x0d0c0f0e,0x01000302,0x05040706,0x09080b0a,0x0d0c0f0e));
    if (bits == 8u)
        return _mm256_shuffle_epi8(value,_mm256_setr_epi32(0x00030201,0x04070605,0x080b0a09,0x0c0f0e0d,0x00030201,0x04070605,0x080b0a09,0x0c0f0e0d));
    return _mm256_or_si256(_mm256_srli_epi32(value,bits),_mm256_slli_epi32(value,32u-bits));
}

static inline __attribute__((always_inline)) void permute(__m256i *restrict state, const __m256i *restrict message) {
#pragma GCC unroll 10
    for (unsigned round = 0; round < 10; ++round) {
#pragma GCC unroll 8
        for (unsigned group = 0; group < 8; ++group) {
            unsigned a = group%4u, diagonal = group/4u;
            unsigned b = 4u+(a+diagonal)%4u, c = 8u+(a+2u*diagonal)%4u, d = 12u+(a+3u*diagonal)%4u;
            state[a] = _mm256_add_epi32(_mm256_add_epi32(state[a],state[b]),message[blake2s_sigma[round][2u*group]]);
            state[d] = rotate(_mm256_xor_si256(state[d],state[a]),16);
            state[c] = _mm256_add_epi32(state[c],state[d]);
            state[b] = rotate(_mm256_xor_si256(state[b],state[c]),12);
            state[a] = _mm256_add_epi32(_mm256_add_epi32(state[a],state[b]),message[blake2s_sigma[round][2u*group+1u]]);
            state[d] = rotate(_mm256_xor_si256(state[d],state[a]),8);
            state[c] = _mm256_add_epi32(state[c],state[d]);
            state[b] = rotate(_mm256_xor_si256(state[b],state[c]),7);
        }
    }
}

static inline __attribute__((always_inline)) void transpose8(__m256i *restrict output, const __m256i *restrict input) {
    __m256i a0 = _mm256_unpacklo_epi32(input[0],input[1]), a1 = _mm256_unpackhi_epi32(input[0],input[1]);
    __m256i a2 = _mm256_unpacklo_epi32(input[2],input[3]), a3 = _mm256_unpackhi_epi32(input[2],input[3]);
    __m256i a4 = _mm256_unpacklo_epi32(input[4],input[5]), a5 = _mm256_unpackhi_epi32(input[4],input[5]);
    __m256i a6 = _mm256_unpacklo_epi32(input[6],input[7]), a7 = _mm256_unpackhi_epi32(input[6],input[7]);
    __m256i b0 = _mm256_unpacklo_epi64(a0,a2), b1 = _mm256_unpackhi_epi64(a0,a2);
    __m256i b2 = _mm256_unpacklo_epi64(a1,a3), b3 = _mm256_unpackhi_epi64(a1,a3);
    __m256i b4 = _mm256_unpacklo_epi64(a4,a6), b5 = _mm256_unpackhi_epi64(a4,a6);
    __m256i b6 = _mm256_unpacklo_epi64(a5,a7), b7 = _mm256_unpackhi_epi64(a5,a7);
    output[0] = _mm256_permute2x128_si256(b0,b4,0x20); output[4] = _mm256_permute2x128_si256(b0,b4,0x31);
    output[1] = _mm256_permute2x128_si256(b1,b5,0x20); output[5] = _mm256_permute2x128_si256(b1,b5,0x31);
    output[2] = _mm256_permute2x128_si256(b2,b6,0x20); output[6] = _mm256_permute2x128_si256(b2,b6,0x31);
    output[3] = _mm256_permute2x128_si256(b3,b7,0x20); output[7] = _mm256_permute2x128_si256(b3,b7,0x31);
}

static inline void load_messages(__m256i message[16], const uint8_t *const keys[8], unsigned key_bytes) {
    if (key_bytes == 64u) {
        __m256i rows[8];
        for (unsigned half = 0; half < 2; ++half) {
            for (unsigned j = 0; j < 8; ++j)
                rows[j] = _mm256_loadu_si256((const __m256i *)(const void *)(keys[j]+32u*half));
            transpose8(message+8u*half,rows);
        }
        sydo_wipe(rows,sizeof(rows));
    } else {
        uint32_t words[8];
        for (unsigned word = 0; word < 16; ++word) {
            unsigned first = 4u*word;
            for (unsigned j = 0; j < 8; ++j) {
                words[j] = 0;
                for (unsigned byte = 0; byte < 4 && first+byte < key_bytes; ++byte)
                    words[j] |= (uint32_t)keys[j][first+byte] << (8u*byte);
            }
            message[word] = _mm256_loadu_si256((const __m256i *)(const void *)words);
        }
        sydo_wipe(words,sizeof(words));
    }
}

static inline void store_states(uint8_t *const *output, size_t count, size_t offset, size_t bytes,
                                  const __m256i state[16], unsigned clear) {
    __m256i rows[8];
    uint8_t fragment[32];
    for (unsigned half = 0; half < 2 && 32u*half < bytes; ++half) {
        size_t taken = bytes-32u*half < 32u ? bytes-32u*half : 32u;
        transpose8(rows,state+8u*half);
        for (size_t j = 0; j < count; ++j) {
            uint8_t *destination = output[j]+offset+32u*half;
            if (taken == 32u) _mm256_storeu_si256((__m256i *)(void *)destination,rows[j]);
            else { _mm256_storeu_si256((__m256i *)(void *)fragment,rows[j]); memcpy(destination,fragment,taken); }
        }
    }
    if (clear) { sydo_wipe(rows,sizeof(rows)); sydo_wipe(fragment,sizeof(fragment)); }
}

void cipher_encrypt(const sydo_cipher_keys *expanded, const uint8_t *input, size_t input_stride,
                     uint8_t *output, size_t output_stride, size_t lanes) {
    __m256i message[16], state[16];
    if (expanded->lanes == 1u)
        for (unsigned word = 0; word < 16; ++word)
            message[word] = _mm256_set1_epi32((int)sydo_load32(expanded->keys[0].key+4u*word));
    for (size_t first = 0; first < lanes; first += 8u) {
        size_t count = lanes-first < 8u ? lanes-first : 8u;
        const uint8_t *keys[8];
        for (unsigned j = 0; j < 8; ++j) {
            size_t lane = first+(j < count ? j : 0);
            keys[j] = expanded->keys[expanded->lanes == 1u ? 0 : lane].key;
        }
        if (expanded->lanes != 1u) load_messages(message,keys,SYDO_CIPHER_KEY_BYTES);
        const uint8_t *inputs[8];
        for (unsigned j = 0; j < 8; ++j) inputs[j] = input+(first+(j < count ? j : 0))*input_stride;
        load_messages(state,inputs,64);
        permute(state,message);
        uint8_t *destinations[8];
        for (size_t j = 0; j < count; ++j) destinations[j] = output+(first+j)*output_stride;
        store_states(destinations,count,0,64,state,1);
    }
    sydo_wipe(message,sizeof(message)); sydo_wipe(state,sizeof(state));
}

void blake2s_matrix_blocks(uint8_t *output, size_t stride, const uint8_t key[64], uint32_t first, size_t count) {
    __m256i message[16], state[16];
    for (unsigned word = 0; word < 16; ++word)
        message[word] = _mm256_set1_epi32((int)sydo_load32(key+4u*word));
    for (size_t offset = 0; offset < count; offset += 8u) {
        size_t taken = count-offset < 8u ? count-offset : 8u;
        state[0] = _mm256_setr_epi32((int)(first+(uint32_t)(offset+0u)),(int)(first+(uint32_t)(offset+1u)),
            (int)(first+(uint32_t)(offset+2u)),(int)(first+(uint32_t)(offset+3u)),
            (int)(first+(uint32_t)(offset+4u)),(int)(first+(uint32_t)(offset+5u)),
            (int)(first+(uint32_t)(offset+6u)),(int)(first+(uint32_t)(offset+7u)));
        for (unsigned word = 1; word < 16; ++word) state[word] = _mm256_setzero_si256();
        permute(state,message);
        uint8_t *destinations[8];
        for (size_t j = 0; j < taken; ++j) destinations[j] = output+(offset+j)*stride;
        store_states(destinations,taken,0,64,state,0);
    }
}

static void generate(const uint8_t *const *keys, unsigned key_bytes,
                     const uint8_t iv[SYDO_SEED_BYTES], const uint32_t *tweaks,
                     uint8_t *const *output, size_t lanes, size_t output_bytes, unsigned block_output_bytes) {
    __m256i message[16], state[16], initial[16];
    uint32_t adjusted[8];
    size_t count_blocks = (output_bytes+block_output_bytes-1u)/block_output_bytes;
    for (unsigned word = 0; word < 16; ++word) initial[word] = _mm256_set1_epi32((int)sydo_load32(iv+4u*word));
    for (size_t first = 0; first < lanes; first += 8u) {
        size_t count = lanes-first < 8u ? lanes-first : 8u;
        const uint8_t *selected[8];
        for (unsigned j = 0; j < 8; ++j) {
            size_t lane = first+(j < count ? j : 0);
            selected[j] = keys[lane];
            adjusted[j] = sydo_load32(iv+60u)+tweaks[lane];
        }
        load_messages(message,selected,key_bytes);
        for (size_t block = 0; block < count_blocks; ++block) {
            memcpy(state,initial,sizeof(state));
            state[0] = _mm256_add_epi32(state[0],_mm256_set1_epi32((int)(uint32_t)block));
            state[15] = _mm256_loadu_si256((const __m256i *)(const void *)adjusted);
            permute(state,message);
                size_t offset = block*block_output_bytes;
            size_t taken = output_bytes-offset < block_output_bytes ? output_bytes-offset : block_output_bytes;
            store_states(output+first,count,offset,taken,state,1);
        }
    }
    sydo_wipe(message,sizeof(message)); sydo_wipe(state,sizeof(state));
    sydo_wipe(adjusted,sizeof(adjusted));
}

void cipher_generate_pair(const uint8_t *const *keys, unsigned key_bytes,
                     const uint8_t iv[SYDO_SEED_BYTES], const uint32_t *tweaks,
                     uint8_t *const *output, size_t lanes, size_t output_bytes, unsigned block_output_bytes) {
    generate(keys,key_bytes,iv,tweaks,output,lanes,output_bytes,block_output_bytes);
}

void cipher_generate_stream(const sydo_cipher_keys *expanded, const uint8_t iv[SYDO_SEED_BYTES],
                     const uint32_t *tweaks, uint8_t *const *output, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes) {
    const uint8_t *keys[64];
    for (size_t j = 0; j < lanes; ++j) keys[j] = expanded->keys[expanded->lanes == 1u ? 0 : j].key;
    generate(keys,SYDO_CIPHER_KEY_BYTES,iv,tweaks,output,lanes,output_bytes,block_output_bytes);
}

void cipher_generate_pair_jobs(const sydo_prg_job *jobs, unsigned key_bytes,
                     const uint8_t iv[SYDO_SEED_BYTES], size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes) {
    if (!lanes || !output_bytes) return;
    for (size_t first = 0; first < lanes; first += 64u) {
        size_t count = lanes-first < 64u ? lanes-first : 64u;
        const uint8_t *keys[64];
        uint8_t *output[64];
        uint32_t tweaks[64];
        for (size_t j = 0; j < count; ++j) {
            keys[j] = jobs[first+j].seed;
            output[j] = jobs[first+j].output;
            tweaks[j] = jobs[first+j].tweak;
        }
        cipher_generate_pair(keys, key_bytes, iv, tweaks, output, count, output_bytes, block_output_bytes);
    }
}

void cipher_generate_stream_jobs(const sydo_cipher_keys *expanded, const uint8_t iv[SYDO_SEED_BYTES],
                     const sydo_prg_job *jobs, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes) {
    if (!lanes || !output_bytes) return;
    for (size_t first = 0; first < lanes; first += 64u) {
        size_t count = lanes-first < 64u ? lanes-first : 64u;
        uint8_t *output[64];
        uint32_t tweaks[64];
        for (size_t j = 0; j < count; ++j) {
            output[j] = jobs[first+j].output;
            tweaks[j] = jobs[first+j].tweak;
        }
        sydo_cipher_keys part = *expanded;
        if (part.lanes != 1u) { part.keys += first; part.lanes = count; }
        cipher_generate_stream(&part, iv, tweaks, output, count, output_bytes, block_output_bytes);
    }
}
