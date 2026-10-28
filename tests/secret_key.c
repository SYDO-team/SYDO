#include "sydo.h"
#include "keygen.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t entropy[SYDO_KEYGEN_SEED_BYTES], pk[SYDO_PK_BYTES];
    uint8_t sk[SYDO_SK_BYTES], changed[SYDO_SK_BYTES];
    unsigned checked = 0;
    for (unsigned trial = 0; trial < 4; ++trial) {
        for (unsigned i = 0; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)(19u*i + 37u*trial);
        if (sydo_keygen_from_seed(pk, sizeof(pk), sk, sizeof(sk), entropy, sizeof(entropy)) ||
            sydo_validate_secret_key(sk)) return 1;
        for (unsigned bit = 0; bit < SYDO_WITNESS_BYTES * 8u; ++bit) {
            memcpy(changed, sk, sizeof(sk));
            changed[SYDO_SK_WITNESS_OFFSET + bit/8u] ^= (uint8_t)(1u << (bit%8u));
            if (!sydo_validate_secret_key(changed)) {
                fprintf(stderr, "witness bit %u was accepted\n", bit);
                return 1;
            }
            ++checked;
        }
        for (unsigned i = 0; i < SYDO_PK_BYTES; ++i) {
            memcpy(changed, sk, sizeof(sk));
            changed[i] ^= 1;
            if (!sydo_validate_secret_key(changed)) return 1;
            ++checked;
        }
        memcpy(changed, sk, sizeof(sk));
        for (unsigned i = 0; i < SYDO_SEED_BYTES; ++i) changed[SYDO_PK_BYTES+i] ^= (uint8_t)(i+1u);
        if (sydo_validate_secret_key(changed)) return 1;
    }
    printf("secret-key witness and public relation: %u corruptions rejected\n", checked);
    return 0;
}
