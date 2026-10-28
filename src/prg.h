#ifndef SYDO_PRG_H
#define SYDO_PRG_H

#include <stddef.h>
#include <stdint.h>
#include "cipher.h"
#include "parameters.h"

typedef struct {
    _Alignas(64) sydo_cipher_round_keys round_keys[SYDO_CIPHER_BATCH_KEYS];
    _Alignas(64) uint8_t keys[64][SYDO_CIPHER_KEY_BYTES], input[64][SYDO_CIPHER_KEY_BYTES], output[64][SYDO_CIPHER_KEY_BYTES];
    uint8_t streams[64][SYDO_VOLE_STRIDE];
} sydo_prg_workspace;

/* Output concatenates block prefixes of block_output_bytes bytes.
 * The caller clears the workspace after use. */
void prg_batch(sydo_prg_workspace *workspace, const sydo_prg_job *jobs, size_t count, const uint8_t iv[SYDO_SEED_BYTES],
                size_t output_bytes, unsigned block_output_bytes);

#endif
