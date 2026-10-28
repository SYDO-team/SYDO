#ifndef SYDO_VOLE_H
#define SYDO_VOLE_H

#include "bavc.h"

void vole_commit(const sydo_bavc *tree, const uint8_t iv[SYDO_SEED_BYTES], uint8_t u[SYDO_VOLE_BYTES],
                   uint8_t *columns, uint8_t *corrections);
void vole_reconstruct(const sydo_bavc *tree, const uint8_t iv[SYDO_SEED_BYTES],
                        const uint8_t challenge[SYDO_SEED_BYTES], const uint8_t *corrections, uint8_t *columns);
void vole_hash(uint8_t output[SYDO_VOLE_HASH_BYTES], const uint8_t seed[SYDO_CHALLENGE1_BYTES],
                 const uint8_t column[SYDO_VOLE_BYTES]);

void vole_hash_batch(uint8_t *output, size_t output_stride, const uint8_t seed[SYDO_CHALLENGE1_BYTES],
                       const uint8_t *columns, size_t column_stride, size_t count);

#endif
