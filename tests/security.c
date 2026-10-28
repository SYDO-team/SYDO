#include "sydo.h"
#include "signature.h"
#include "bavc.h"
#include "rsd.h"
#include "bytes.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int signature_tests(const uint8_t *pk, const uint8_t *sk) {
    const size_t lengths[] = {0, 1, 63, 64, 65, 8191, 8192, 8193};
    uint8_t *message = malloc(8194), *signature = malloc(SYDO_SIG_BYTES+1u);
    uint8_t *other = malloc(SYDO_SIG_BYTES+1u), rho[SYDO_SEED_BYTES];
    if (!message || !signature || !other) { free(message); free(signature); free(other); return 1; }
    for (unsigned i = 0; i < 8194; ++i) message[i] = (uint8_t)(29u*i+5u);
    memset(rho, 0x39, sizeof(rho));
    int status = 1;
    for (unsigned i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
        size_t n = lengths[i];
        if (sydo_sign_from_seed(signature, SYDO_SIG_BYTES, message, n, sk, SYDO_SK_BYTES, rho, sizeof(rho)) ||
            sydo_verify(signature, SYDO_SIG_BYTES, message, n, pk, SYDO_PK_BYTES) ||
            !sydo_verify(signature, SYDO_SIG_BYTES, message, n+1u, pk, SYDO_PK_BYTES)) goto done;
        message[n/2u] ^= 1;
        int changed = n ? sydo_verify(signature, SYDO_SIG_BYTES, message, n, pk, SYDO_PK_BYTES) : -1;
        message[n/2u] ^= 1;
        if (!changed) goto done;
    }
    if (sydo_sign_from_seed(other, SYDO_SIG_BYTES, message, 8193, sk, SYDO_SK_BYTES, rho, sizeof(rho)) ||
        memcmp(signature, other, SYDO_SIG_BYTES)) goto done;
    rho[0] ^= 1;
    if (sydo_sign_from_seed(other, SYDO_SIG_BYTES, message, 8193, sk, SYDO_SK_BYTES, rho, sizeof(rho)) ||
        !memcmp(signature, other, SYDO_SIG_BYTES) ||
        sydo_verify(other, SYDO_SIG_BYTES, message, 8193, pk, SYDO_PK_BYTES)) goto done;
    if (!sydo_verify(signature, SYDO_SIG_BYTES-1u, message, 8193, pk, SYDO_PK_BYTES) ||
        !sydo_verify(signature, SYDO_SIG_BYTES+1u, message, 8193, pk, SYDO_PK_BYTES)) goto done;
    memset(other, 0, SYDO_SIG_BYTES);
    if (!sydo_verify(other, SYDO_SIG_BYTES, message, 8193, pk, SYDO_PK_BYTES)) goto done;
    memset(other, 0xff, SYDO_SIG_BYTES);
    if (!sydo_verify(other, SYDO_SIG_BYTES, message, 8193, pk, SYDO_PK_BYTES)) goto done;

    uint8_t *hidden = calloc(SYDO_TREE_NODES, 1);
    if (!hidden) goto done;
    for (unsigned row = 0; row < SYDO_TAU; ++row) {
        size_t node = SYDO_TREE_LEAVES-1u + SYDO_TAU*bavc_index(signature+SIGNATURE_CHALLENGE,row) + row;
        for (;;) { hidden[node] = 1; if (!node) break; node = (node-1u)/2u; }
    }
    size_t boundary = 0;
    for (size_t node = 0; node < SYDO_TREE_LEAVES-1u; ++node)
        boundary += hidden[2u*node+1u] != hidden[2u*node+2u];
    free(hidden);
    size_t start = SIGNATURE_OPENING + (2u*SYDO_TAU+boundary)*SYDO_SEED_BYTES;
    if (start > SIGNATURE_CHALLENGE) goto done;
    for (size_t offset = start; offset < SIGNATURE_CHALLENGE; ++offset) {
        if (signature[offset]) goto done;
        signature[offset] = 1;
        int accepted = !sydo_verify(signature,SYDO_SIG_BYTES,message,8193,pk,SYDO_PK_BYTES);
        signature[offset] = 0;
        if (accepted) goto done;
    }
    for (unsigned bit = 0; bit < SYDO_GRIND_BITS; ++bit) {
        signature[SIGNATURE_CHALLENGE+SYDO_SEED_BYTES-1u] ^= (uint8_t)(1u << (7u-bit));
        int accepted = !sydo_verify(signature,SYDO_SIG_BYTES,message,8193,pk,SYDO_PK_BYTES);
        signature[SIGNATURE_CHALLENGE+SYDO_SEED_BYTES-1u] ^= (uint8_t)(1u << (7u-bit));
        if (accepted) goto done;
    }
    printf("message boundaries, repeated randomness, exact lengths, zero inputs, %zu padding bytes and grinding bits verified\n",(size_t)SIGNATURE_CHALLENGE-start);
    status = 0;
done:
    free(message); free(signature); free(other);
    return status;
}

static int constraint_tests(const uint8_t *pk, const uint8_t *sk) {
    size_t bytes = SYDO_LAMBDA*SYDO_VOLE_STRIDE;
    uint8_t *v = malloc(bytes), *q = malloc(bytes);
    uint8_t u[SYDO_VOLE_BYTES], d[SYDO_WITNESS_BYTES], challenge[SYDO_CHALLENGE2_BYTES];
    uint8_t delta[SYDO_SEED_BYTES], proof[SYDO_PROOF_BYTES], expected[SYDO_SEED_BYTES], actual[SYDO_SEED_BYTES];
    if (!v || !q) { free(v); free(q); return 1; }
    for (size_t i = 0; i < bytes; ++i) v[i] = (uint8_t)(13u*i+7u);
    for (unsigned i = 0; i < sizeof(u); ++i) u[i] = (uint8_t)(11u*i+3u);
    for (unsigned i = 0; i < sizeof(d); ++i) d[i] = sk[SYDO_SK_WITNESS_OFFSET+i] ^ u[i];
    int status = 1;
    for (unsigned trial = 0; trial < 4; ++trial) {
        for (unsigned i = 0; i < sizeof(challenge); ++i)
            challenge[i] = trial == 0 ? 0 : trial == 1 ? 1 : trial == 2 ? 0xff : (uint8_t)(17u*i+9u);
        if (rsd_prove(proof,expected,pk,sk+SYDO_SK_WITNESS_OFFSET,u,v,challenge)) goto done;
        for (unsigned shape = 0; shape < 3; ++shape) {
            memset(delta, shape == 2 ? 0xff : 0, sizeof(delta));
            if (shape == 1) delta[0] = 1;
            memcpy(q,v,bytes);
            for (unsigned col = 0; col < SYDO_LAMBDA; ++col)
                for (unsigned row = 0; row < SYDO_VOLE_BYTES; ++row)
                    q[col*SYDO_VOLE_STRIDE+row] ^= (uint8_t)((0u-sydo_bit(delta,col)) & u[row]);
            if (rsd_verify(actual,pk,d,q,challenge,delta,proof) || memcmp(expected,actual,sizeof(actual))) goto done;
        }
    }
    puts("zero, one and full-width challenges: 12 prover/verifier algebra comparisons passed");
    status = 0;
done:
    free(v); free(q);
    return status;
}

int main(void) {
    uint8_t entropy[SYDO_KEYGEN_SEED_BYTES], pk[SYDO_PK_BYTES], sk[SYDO_SK_BYTES];
    for (unsigned i = 0; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)(18u+17u*i);
    if (sydo_keygen_from_seed(pk,sizeof(pk),sk,sizeof(sk),entropy,sizeof(entropy))) return 1;
    if (signature_tests(pk,sk) || constraint_tests(pk,sk)) return 1;
    return 0;
}
