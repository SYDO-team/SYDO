#ifndef SYDO_RSD_H
#define SYDO_RSD_H

#include "parameters.h"

int rsd_prove(uint8_t proof[SYDO_PROOF_BYTES], uint8_t check[SYDO_SEED_BYTES], const uint8_t pk[SYDO_PK_BYTES],
                const uint8_t witness[SYDO_WITNESS_BYTES], const uint8_t u[SYDO_VOLE_BYTES],
                const uint8_t *columns, const uint8_t challenge[SYDO_CHALLENGE2_BYTES]);
int rsd_verify(uint8_t check[SYDO_SEED_BYTES], const uint8_t pk[SYDO_PK_BYTES], const uint8_t correction[SYDO_WITNESS_BYTES],
                 const uint8_t *columns, const uint8_t challenge[SYDO_CHALLENGE2_BYTES],
                 const uint8_t delta[SYDO_SEED_BYTES], const uint8_t proof[SYDO_PROOF_BYTES]);

#endif
