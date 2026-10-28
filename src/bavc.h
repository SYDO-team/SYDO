#ifndef SYDO_BAVC_H
#define SYDO_BAVC_H

#include "parameters.h"
#include "prg.h"

typedef struct { uint8_t *nodes; uint8_t *commitments; sydo_prg_workspace *workspace; uint8_t *allocation; uint8_t iv[SYDO_SEED_BYTES]; } sydo_bavc;

int bavc_commit(sydo_bavc *state, uint8_t digest[SYDO_COMMITMENT_BYTES], const uint8_t root[SYDO_SEED_BYTES], const uint8_t iv[SYDO_SEED_BYTES]);
int bavc_reconstruct(sydo_bavc *state, uint8_t digest[SYDO_COMMITMENT_BYTES], const uint8_t *opening,
                       const uint8_t challenge[SYDO_SEED_BYTES], const uint8_t iv[SYDO_SEED_BYTES]);
int bavc_open(const sydo_bavc *state, uint8_t *opening, const uint8_t challenge[SYDO_SEED_BYTES]);
void bavc_clear_workspace(sydo_bavc *state);
void bavc_clear(sydo_bavc *state);
unsigned bavc_index(const uint8_t challenge[SYDO_SEED_BYTES], unsigned row);

#endif
