#include "bavc.h"
#include "vole.h"
#include "hash.h"
#include "bytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compare(FILE *f, const uint8_t *data, size_t bytes, const char *name) {
    for (size_t i = 0; i < bytes; ++i)
        if (fgetc(f) != data[i]) { fprintf(stderr, "%s differs at byte %zu\n", name, i); return 1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s COMPONENT_FIXTURE\n", argv[0]); return 2; }
    FILE *fixture = fopen(argv[1], "rb");
    if (!fixture) return 2;
    sydo_bavc sender = {0}, receiver = {0};
    uint8_t root[SYDO_SEED_BYTES], iv[SYDO_SEED_BYTES], com[SYDO_COMMITMENT_BYTES], reconstructed[SYDO_COMMITMENT_BYTES], challenge[SYDO_SEED_BYTES] = {0};
    uint8_t u[SYDO_VOLE_BYTES], hash[SYDO_VOLE_HASH_BYTES], seed[SYDO_CHALLENGE1_BYTES];
    uint8_t *v = malloc(SYDO_LAMBDA * SYDO_VOLE_STRIDE), *q = malloc(SYDO_LAMBDA * SYDO_VOLE_STRIDE);
    uint8_t *c = malloc(SYDO_CORRECTIONS_BYTES), *opening = malloc(SYDO_OPEN_BYTES);
    int status = 1;
    if (!v || !q || !c || !opening) goto done;
    for (unsigned i = 0; i < SYDO_SEED_BYTES; ++i) { root[i] = (uint8_t)i; iv[i] = (uint8_t)(128 + i); }
    for (unsigned i = 0; i < SYDO_CHALLENGE1_BYTES; ++i) seed[i] = (uint8_t)(11 + 7 * i);
    if (bavc_commit(&sender, com, root, iv)) goto done;
    vole_commit(&sender, iv, u, v, c);
    vole_hash(hash, seed, u);
    if (compare(fixture, com, SYDO_COMMITMENT_BYTES, "BAVC digest") || compare(fixture, u, sizeof(u), "VOLE u")) goto done;
    for (unsigned col = 0; col < SYDO_LAMBDA; ++col)
        if (compare(fixture, v + col * SYDO_VOLE_STRIDE, SYDO_VOLE_BYTES, "VOLE column")) goto done;
    if (compare(fixture, c, SYDO_CORRECTIONS_BYTES, "VOLE corrections") || compare(fixture, hash, SYDO_VOLE_HASH_BYTES, "VOLE hash")) goto done;
    uint8_t opening_seed[SYDO_SEED_BYTES + 4u];
    memcpy(opening_seed, iv, SYDO_SEED_BYTES);
    for (unsigned attempt = 0; ; ++attempt) {
        sydo_store32(opening_seed + SYDO_SEED_BYTES, attempt);
        if (sydo_xof(challenge, sizeof(challenge), opening_seed, sizeof(opening_seed))) goto done;
        challenge[SYDO_SEED_BYTES - 1u] &= (uint8_t)(255u >> SYDO_GRIND_BITS);
        int opened = bavc_open(&sender, opening, challenge);
        if (!opened) break;
        if (opened < 0 || attempt > 65536) { fputs("opening search failed\n", stderr); goto done; }
    }
    if (bavc_reconstruct(&receiver, reconstructed, opening, challenge, iv) || memcmp(com, reconstructed, SYDO_COMMITMENT_BYTES)) goto done;
    vole_reconstruct(&receiver, iv, challenge, c, q);
    for (unsigned col = 0; col < SYDO_LAMBDA; ++col)
        for (unsigned row = 0; row < SYDO_VOLE_BYTES; ++row)
            if (q[col * SYDO_VOLE_STRIDE + row] !=
                (v[col * SYDO_VOLE_STRIDE + row] ^ ((0u - ((challenge[col / 8] >> (col % 8)) & 1u)) & u[row]))) {
                fprintf(stderr, "VOLE correlation failed at column %u, byte %u\n", col, row); goto done;
            }
    for (unsigned col = 0; col < SYDO_LAMBDA; ++col)
        for (unsigned row = SYDO_VOLE_BYTES; row < SYDO_VOLE_STRIDE; ++row)
            if (v[col * SYDO_VOLE_STRIDE + row] || q[col * SYDO_VOLE_STRIDE + row]) goto done;
    puts(SYDO_INSTANCE ": BAVC/VOLE fixtures, commitment and correlation verified");
    status = 0;
done:
    fclose(fixture);
    bavc_clear(&sender); bavc_clear(&receiver);
    free(v); free(q); free(c); free(opening);
    return status;
}
