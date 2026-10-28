#include "profile.h"
#include "hash.h"
#include "bytes.h"
#include "auxfunc.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int sydo_xof(uint8_t *output, size_t output_bytes,
              const void *input, size_t input_bytes) {
    const uint8_t empty = 0;
    if ((!output && output_bytes) || (!input && input_bytes) ||
        input_bytes > ULLONG_MAX / 8u || output_bytes >= (UINT64_C(1) << 37) - 32u)
        return -1;
    SYDO_PROFILE_BEGIN(PROFILE_XOF);
    int status = pseudoXOF((unsigned long long)output_bytes * 8u,
                     input_bytes ? (const uint8_t *)input : &empty,
                     (unsigned long long)input_bytes * 8u, output);
    SYDO_PROFILE_END(PROFILE_XOF);
    return status;
}

int sydo_hash(uint8_t *output, size_t output_bytes, uint8_t domain,
               const sydo_hash_part *parts, size_t count) {
    size_t size = 1;
    for (size_t i = 0; i < count; ++i) {
        if (parts[i].bytes > SIZE_MAX - size || (!parts[i].data && parts[i].bytes)) return -1;
        size += parts[i].bytes;
    }
    uint8_t *buffer = malloc(size);
    if (!buffer) return -2;
    size_t offset = 0;
    for (size_t i = 0; i < count; ++i) {
        if (parts[i].bytes) memcpy(buffer + offset, parts[i].data, parts[i].bytes);
        offset += parts[i].bytes;
    }
    buffer[offset] = domain;
    int status = sydo_xof(output, output_bytes, buffer, size);
    sydo_wipe(buffer, size);
    free(buffer);
    return status;
}

void sydo_grinding_init(sydo_grinding_hash *hash, const uint8_t challenge[SYDO_CHALLENGE2_BYTES],
                         const uint8_t check[SYDO_SEED_BYTES], const uint8_t proof[SYDO_PROOF_BYTES]) {
    memcpy(hash->input, challenge, SYDO_CHALLENGE2_BYTES);
    memcpy(hash->input + SYDO_CHALLENGE2_BYTES, check, SYDO_SEED_BYTES);
    memcpy(hash->input + SYDO_CHALLENGE2_BYTES + SYDO_SEED_BYTES, proof, SYDO_PROOF_BYTES);
    hash->input[SYDO_GRINDING_PREFIX_BYTES + 4u] = 11;
}

int sydo_grinding_hashes(uint8_t output[SYDO_GRINDING_LANES][SYDO_SEED_BYTES],
                          sydo_grinding_hash *hash, uint32_t first, unsigned count) {
    if (count > SYDO_GRINDING_LANES) return -1;
    if (!count) return 0;
    sydo_store32(hash->input + SYDO_GRINDING_PREFIX_BYTES, first);
    return sydo_xof(output[0], SYDO_SEED_BYTES, hash->input, sizeof(hash->input));
}
