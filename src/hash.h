#ifndef SYDO_HASH_H
#define SYDO_HASH_H

#include "parameters.h"
#include <stddef.h>
#include <stdint.h>

typedef struct { const void *data; size_t bytes; } sydo_hash_part;

int sydo_xof(uint8_t *output, size_t output_bytes,
              const void *input, size_t input_bytes);
int sydo_hash(uint8_t *output, size_t output_bytes, uint8_t domain,
               const sydo_hash_part *parts, size_t count);

#define SYDO_GRINDING_PREFIX_BYTES (SYDO_CHALLENGE2_BYTES + SYDO_SEED_BYTES + SYDO_PROOF_BYTES)
#define SYDO_GRINDING_LANES 1u
_Static_assert(SYDO_GRINDING_LANES == 1u, "Grinding processes one candidate per call");
typedef struct { uint8_t input[SYDO_GRINDING_PREFIX_BYTES + 5u]; } sydo_grinding_hash;

void sydo_grinding_init(sydo_grinding_hash *hash, const uint8_t challenge[SYDO_CHALLENGE2_BYTES],
                         const uint8_t check[SYDO_SEED_BYTES], const uint8_t proof[SYDO_PROOF_BYTES]);
int sydo_grinding_hashes(uint8_t output[SYDO_GRINDING_LANES][SYDO_SEED_BYTES],
                          sydo_grinding_hash *hash, uint32_t first, unsigned count);

#endif
