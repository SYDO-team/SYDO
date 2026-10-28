#include "sydo.h"
#include "signature.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t entropy[SYDO_KEYGEN_SEED_BYTES], rho[SYDO_SEED_BYTES];
    uint8_t pk[SYDO_PK_BYTES], sk[SYDO_SK_BYTES], changed_sk[SYDO_SK_BYTES];
    uint8_t message[] = "SYDO input validation";
    uint8_t *signature = malloc(SYDO_SIG_BYTES + 1), *changed = malloc(SYDO_SIG_BYTES + 1);
    if (!signature || !changed) return 2;
    for (unsigned i = 0; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)(18 + 17 * i);
    for (unsigned i = 0; i < sizeof(rho); ++i) rho[i] = (uint8_t)(32 + 17 * i);
    if (sydo_keygen_from_seed(pk, sizeof(pk), sk, sizeof(sk), entropy, sizeof(entropy)) ||
        sydo_sign_from_seed(signature, SYDO_SIG_BYTES, message, sizeof(message) - 1, sk, sizeof(sk), rho, sizeof(rho)) ||
        sydo_verify(signature, SYDO_SIG_BYTES, message, sizeof(message) - 1, pk, sizeof(pk))) return 1;
    const size_t positions[] = {0, SYDO_CORRECTIONS_BYTES - 1, SIGNATURE_UHASH, SIGNATURE_WITNESS,
        SIGNATURE_PROOF, SIGNATURE_OPENING, SIGNATURE_CHALLENGE, SIGNATURE_IV, SIGNATURE_COUNTER, SYDO_SIG_BYTES - 1};
    for (unsigned i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        memcpy(changed, signature, SYDO_SIG_BYTES);
        changed[positions[i]] ^= 1;
        if (!sydo_verify(changed, SYDO_SIG_BYTES, message, sizeof(message) - 1, pk, sizeof(pk))) return 1;
    }
    if (!sydo_verify(signature, SYDO_SIG_BYTES - 1, message, sizeof(message) - 1, pk, sizeof(pk)) ||
        !sydo_verify(signature, SYDO_SIG_BYTES + 1, message, sizeof(message) - 1, pk, sizeof(pk)) ||
        !sydo_verify(signature, SYDO_SIG_BYTES, message, sizeof(message) - 1, pk, sizeof(pk) - 1) ||
        !sydo_verify(signature, SYDO_SIG_BYTES, NULL, 1, pk, sizeof(pk)) ||
        !sydo_verify(NULL, SYDO_SIG_BYTES, message, sizeof(message) - 1, pk, sizeof(pk))) return 1;
    memcpy(changed_sk, sk, sizeof(sk)); changed_sk[SYDO_PK_BYTES + SYDO_SEED_BYTES] ^= 1;
    if (!sydo_sign_from_seed(changed, SYDO_SIG_BYTES, message, sizeof(message) - 1, changed_sk, sizeof(changed_sk), rho, sizeof(rho)) ||
        !sydo_sign_from_seed(changed, SYDO_SIG_BYTES - 1, message, sizeof(message) - 1, sk, sizeof(sk), rho, sizeof(rho)) ||
        !sydo_sign_from_seed(changed, SYDO_SIG_BYTES, NULL, 1, sk, sizeof(sk), rho, sizeof(rho)) ||
        !sydo_keygen_from_seed(pk, sizeof(pk) - 1, sk, sizeof(sk), entropy, sizeof(entropy))) return 1;
    if (sydo_sign_from_seed(signature, SYDO_SIG_BYTES, NULL, 0, sk, sizeof(sk), rho, sizeof(rho)) ||
        sydo_verify(signature, SYDO_SIG_BYTES, NULL, 0, pk, sizeof(pk))) return 1;
    free(signature); free(changed);
    puts("signature sections, lengths, malformed secret key, null inputs and empty message verified");
    return 0;
}
