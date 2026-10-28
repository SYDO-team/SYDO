#ifndef SYDO_CIPHER_H
#define SYDO_CIPHER_H

#include "parameters.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SYDO_CIPHER_LANES 64u

typedef struct {
    const uint8_t *seed;
    uint8_t *output;
    uint32_t tweak;
} sydo_prg_job;

typedef struct { uint64_t bits[8]; } sydo_cipher_byte;
#ifdef SYDO_CIPHER_BLAKE2S
typedef struct { uint8_t key[SYDO_CIPHER_KEY_BYTES]; } sydo_cipher_round_keys;
#define SYDO_CIPHER_BATCH_KEYS 64u
#ifdef SYDO_AVX2
#define SYDO_CIPHER_SHARED_LANES 8u
#else
#define SYDO_CIPHER_SHARED_LANES 64u
#endif
#elif defined(SYDO_AVX2)
typedef struct { uint64_t round[SYDO_CIPHER_ROUNDS + 1u][SYDO_CIPHER_BLOCK_BYTES / 8u]; } sydo_cipher_round_keys;
#define SYDO_CIPHER_BATCH_KEYS 64u
#define SYDO_CIPHER_SHARED_LANES 8u
#else
typedef struct { sydo_cipher_byte round[SYDO_CIPHER_ROUNDS + 1u][SYDO_CIPHER_BLOCK_BYTES]; } sydo_cipher_round_keys;
#define SYDO_CIPHER_BATCH_KEYS 1u
#define SYDO_CIPHER_SHARED_LANES 64u
#endif

typedef struct {
    sydo_cipher_round_keys *keys;
    unsigned block_bytes;
    size_t lanes;
} sydo_cipher_keys;

/* Up to 64 independent block encryptions.
 * Set key_stride to zero for one shared key. */
#ifdef SYDO_CIPHER_BLAKE2S
static inline __attribute__((always_inline)) void cipher_expand(sydo_cipher_keys *expanded, sydo_cipher_round_keys *workspace,
                    const uint8_t *keys, size_t key_stride, size_t lanes, unsigned block_bytes) {
    expanded->keys = workspace;
    expanded->block_bytes = block_bytes;
    expanded->lanes = key_stride ? lanes : 1u;
    if (!key_stride || key_stride == sizeof(*workspace))
        memcpy(workspace, keys, expanded->lanes * sizeof(*workspace));
    else
        for (size_t i = 0; i < expanded->lanes; ++i)
            memcpy(workspace[i].key, keys + i*key_stride, SYDO_CIPHER_KEY_BYTES);
}

#else
void cipher_expand(sydo_cipher_keys *expanded, sydo_cipher_round_keys *workspace,
                    const uint8_t *keys,
                    size_t key_stride, size_t lanes, unsigned block_bytes);
#endif
void cipher_encrypt(const sydo_cipher_keys *expanded, const uint8_t *input,
                     size_t input_stride, uint8_t *output,
                     size_t output_stride, size_t lanes);
void cipher_clear(sydo_cipher_keys *expanded);

#ifdef SYDO_AVX2
#ifndef SYDO_CIPHER_BLAKE2S
void cipher_expand_shared(uint8_t *round_keys, size_t round_stride,
                            const uint8_t key[SYDO_CIPHER_KEY_BYTES], unsigned block_bytes);
#endif
/* Generate cipher streams from block prefixes.
 * Short keys are extended with zero bytes to the configured key size. */
void cipher_generate_pair_jobs(const sydo_prg_job *jobs, unsigned key_bytes,
                     const uint8_t iv[SYDO_SEED_BYTES], size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes);
void cipher_generate_stream_jobs(const sydo_cipher_keys *expanded, const uint8_t iv[SYDO_SEED_BYTES],
                     const sydo_prg_job *jobs, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes);
void cipher_generate_pair(const uint8_t *const *keys, unsigned key_bytes, const uint8_t iv[SYDO_SEED_BYTES],
                     const uint32_t *tweaks, uint8_t *const *output, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes);
void cipher_generate_stream(const sydo_cipher_keys *expanded, const uint8_t iv[SYDO_SEED_BYTES],
                     const uint32_t *tweaks, uint8_t *const *output, size_t lanes,
                     size_t output_bytes, unsigned block_output_bytes);
#endif

#endif
