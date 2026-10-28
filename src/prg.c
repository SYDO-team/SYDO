#include "prg.h"
#include "cipher.h"
#include "bytes.h"
#include <string.h>

#if !defined(SYDO_AVX2) || !defined(SYDO_CIPHER_BLAKE2S)
static void generate_blocks(sydo_prg_workspace *workspace, const sydo_prg_job *jobs, size_t count,
                            const uint8_t iv[SYDO_SEED_BYTES], size_t output_bytes, unsigned block_output_bytes) {
    uint8_t (*keys)[SYDO_CIPHER_KEY_BYTES] = workspace->keys;
    sydo_cipher_keys expanded;
#ifdef SYDO_AVX2
    size_t parallel_blocks = 1;
#else
    size_t blocks = (output_bytes + block_output_bytes - 1) / block_output_bytes;
    size_t parallel_blocks = 64 / count;
    if (parallel_blocks > blocks) parallel_blocks = blocks;
#endif
    for (size_t block = 0; block < parallel_blocks; ++block)
        for (size_t j = 0; j < count; ++j) {
            uint8_t *key = keys[block * count + j];
            memcpy(key, jobs[j].seed, SYDO_SEED_BYTES);
            memset(key + SYDO_SEED_BYTES, 0, SYDO_CIPHER_KEY_BYTES - SYDO_SEED_BYTES);
        }
    cipher_expand(&expanded, workspace->round_keys, keys[0], SYDO_CIPHER_KEY_BYTES, parallel_blocks * count, SYDO_CIPHER_BLOCK_BYTES);
#ifdef SYDO_AVX2
    cipher_generate_stream_jobs(&expanded, iv, jobs, count, output_bytes, block_output_bytes);
#else
    uint8_t (*input)[SYDO_CIPHER_KEY_BYTES] = workspace->input;
    uint8_t (*output)[SYDO_CIPHER_KEY_BYTES] = workspace->output;
    /* Job counts and tweaks are public. */
    int shared_input = parallel_blocks == 1;
    for (size_t j = 1; j < count; ++j) shared_input &= jobs[j].tweak == jobs[0].tweak;
    for (size_t first = 0; first < blocks; first += parallel_blocks) {
        size_t taken = blocks - first < parallel_blocks ? blocks - first : parallel_blocks;
        for (size_t c = 0; c < taken; ++c)
            for (size_t j = 0; j < (shared_input ? 1u : count); ++j) {
                uint8_t *p = input[c * count + j];
                memcpy(p, iv, SYDO_SEED_BYTES);
                memset(p + SYDO_SEED_BYTES, 0, SYDO_CIPHER_KEY_BYTES - SYDO_SEED_BYTES);
                sydo_store32(p, sydo_load32(iv) + (uint32_t)(first + c));
                sydo_store32(p + SYDO_SEED_BYTES - 4, sydo_load32(iv + SYDO_SEED_BYTES - 4) + jobs[j].tweak);
            }
        cipher_encrypt(&expanded, input[0], shared_input ? 0 : SYDO_CIPHER_KEY_BYTES, output[0], SYDO_CIPHER_KEY_BYTES, taken * count);
        for (size_t c = 0; c < taken; ++c) {
            size_t offset = (first + c) * block_output_bytes;
            size_t bytes = output_bytes - offset < block_output_bytes ? output_bytes - offset : block_output_bytes;
            for (size_t j = 0; j < count; ++j)
                memcpy(jobs[j].output + offset, output[c * count + j], bytes);
        }
    }
#endif
}

#endif

void prg_batch(sydo_prg_workspace *workspace, const sydo_prg_job *jobs, size_t count, const uint8_t iv[SYDO_SEED_BYTES],
                size_t output_bytes, unsigned block_output_bytes) {
#ifdef SYDO_AVX2
#ifdef SYDO_CIPHER_BLAKE2S
    (void)workspace;
    cipher_generate_pair_jobs(jobs, SYDO_SEED_BYTES, iv, count, output_bytes, block_output_bytes);
#else
    if (output_bytes <= 2u * block_output_bytes) {
        cipher_generate_pair_jobs(jobs, SYDO_SEED_BYTES, iv, count, output_bytes, block_output_bytes);
        return;
    }
    enum { batch = 32 };
    for (size_t first = 0; first < count; first += batch) {
        size_t taken = count-first < batch ? count-first : batch;
        generate_blocks(workspace,jobs+first,taken,iv,output_bytes,block_output_bytes);
    }
#endif
#else
    generate_blocks(workspace,jobs,count,iv,output_bytes,block_output_bytes);
#endif
}
