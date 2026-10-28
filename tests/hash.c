#include "hash.h"
#include "auxfunc.h"
#include "bytes.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    uint8_t challenge[SYDO_CHALLENGE2_BYTES], check[SYDO_SEED_BYTES], proof[SYDO_PROOF_BYTES];
    for (unsigned j = 0; j < sizeof(challenge); ++j) challenge[j] = (uint8_t)(13u*j + 7u);
    for (unsigned j = 0; j < sizeof(check); ++j) check[j] = (uint8_t)(17u*j + 9u);
    for (unsigned j = 0; j < sizeof(proof); ++j) proof[j] = (uint8_t)(19u*j + 11u);
    sydo_grinding_hash grinding;
    sydo_grinding_init(&grinding, challenge, check, proof);
    uint8_t hashes[SYDO_GRINDING_LANES][SYDO_SEED_BYTES], digest[SYDO_SEED_BYTES];
    const uint32_t starts[] = {0,1,UINT32_MAX - 7u,UINT32_MAX - 2u};
    for (unsigned k = 0; k < sizeof(starts)/sizeof(starts[0]); ++k)
        for (unsigned count = 0; count <= SYDO_GRINDING_LANES; ++count) {
            memset(hashes, 0xa5, sizeof(hashes));
            if (sydo_grinding_hashes(hashes, &grinding, starts[k], count)) return 1;
            for (unsigned lane = 0; lane < SYDO_GRINDING_LANES; ++lane) {
                if (lane < count) {
                    uint8_t counter[4]; sydo_store32(counter, starts[k] + lane);
                    uint8_t input[SYDO_GRINDING_PREFIX_BYTES+5u];
                    memcpy(input,challenge,sizeof(challenge)); memcpy(input+sizeof(challenge),check,sizeof(check));
                    memcpy(input+sizeof(challenge)+sizeof(check),proof,sizeof(proof));
                    memcpy(input+SYDO_GRINDING_PREFIX_BYTES,counter,sizeof(counter)); input[sizeof(input)-1u] = 11;
                    if (pseudoXOF(8u*sizeof(digest),input,8u*sizeof(input),digest) || memcmp(digest,hashes[lane],sizeof(digest))) return 1;
                } else for (unsigned j = 0; j < SYDO_SEED_BYTES; ++j) if (hashes[lane][j] != 0xa5) return 1;
            }
        }
    if (sydo_grinding_hashes(hashes, &grinding, 0, SYDO_GRINDING_LANES + 1u) != -1) return 1;
    sydo_wipe(&grinding, sizeof(grinding));
    puts("grinding hashes match NGCC XOF across counter boundaries and partial batches");
    const unsigned input_sizes[] = {0,1,31,32,51,52,55,56,59,60,61,62,63,64,65,115,116,119,120,123,124,125,126,127,128,129,511,512,513,1024,3510,4095,4096};
    const unsigned output_sizes[] = {0,1,20,32,33,40,64,108,128,129,255,256,257,328,392,511,512,513};
    uint8_t xof_input[4096], xof_actual[515], xof_expected[513];
    for (unsigned j = 0; j < sizeof(xof_input); ++j) xof_input[j] = (uint8_t)(23u*j + j/7u);
    for (unsigned i = 0; i < sizeof(input_sizes)/sizeof(input_sizes[0]); ++i)
        for (unsigned o = 0; o < sizeof(output_sizes)/sizeof(output_sizes[0]); ++o) {
            unsigned bytes = output_sizes[o];
            memset(xof_actual, 0xa5, sizeof(xof_actual));
            if (sydo_xof(xof_actual + 1, bytes, xof_input, input_sizes[i]) ||
                pseudoXOF((unsigned long long)bytes*8u, xof_input, (unsigned long long)input_sizes[i]*8u, xof_expected) ||
                memcmp(xof_actual + 1, xof_expected, bytes)) return 1;
            if (xof_actual[0] != 0xa5) return 1;
            for (unsigned j = bytes + 1u; j < sizeof(xof_actual); ++j) if (xof_actual[j] != 0xa5) return 1;
        }
    puts("XOF output matches NGCC across input padding, counter alignment and output boundaries");
    return 0;
}
