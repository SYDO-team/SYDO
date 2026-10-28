#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "parameters.h"
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

DRNG_ctx drng_algorithm;

static int filled(const uint8_t *p, size_t n, uint8_t value) {
    for (size_t i = 0; i < n; ++i) if (p[i] != value) return 0;
    return 1;
}

int main(void) {
    uint8_t seed[64] = {0}, pk[SYDO_PK_BYTES + 16], sk[SYDO_SK_BYTES + 16];
    uint8_t signature[SYDO_SIG_BYTES + 16], message[3] = {1,2,3};
    unsigned long long pk_bytes, sk_bytes, sig_bytes;
    if (init_random_number(&drng_algorithm, seed, sizeof(seed))) return 1;
    if (sig_get_pk_len_bytes() != SYDO_PK_BYTES || sig_get_sk_len_bytes() != SYDO_SK_BYTES ||
        sig_get_sn_len_bytes() != SYDO_SIG_BYTES) return 1;
    for (unsigned trial = 0; trial < 4; ++trial) {
        if (trial) pk_bytes = sk_bytes = sig_bytes = trial == 1 ? 0 : trial == 2 ? 1 : ULLONG_MAX;
        memset(pk, 0xa5, sizeof(pk)); memset(sk, 0xa5, sizeof(sk));
        if (sig_keygen(pk, &pk_bytes, sk, &sk_bytes) || pk_bytes != SYDO_PK_BYTES || sk_bytes != SYDO_SK_BYTES ||
            !filled(pk + SYDO_PK_BYTES, 16, 0xa5) || !filled(sk + SYDO_SK_BYTES, 16, 0xa5)) return 1;
        memset(signature, 0xa5, sizeof(signature));
        if (sig_sign(sk, sk_bytes, message, sizeof(message), signature, &sig_bytes) || sig_bytes != SYDO_SIG_BYTES ||
            !filled(signature + SYDO_SIG_BYTES, 16, 0xa5) ||
            sig_verify(pk, pk_bytes, signature, sig_bytes, message, sizeof(message))) return 1;
    }
    if (sig_keygen(NULL, &pk_bytes, sk, &sk_bytes) >= 0 ||
        sig_sign(sk, sk_bytes, message, sizeof(message), signature, NULL) >= 0 ||
        sig_verify(pk, pk_bytes, signature, sig_bytes - 1, message, sizeof(message)) >= 0) return 1;
    puts("NGCC output lengths, guard bytes and signatures verified");
    return 0;
}
