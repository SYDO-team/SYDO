#include "sydo.h"
#include "keygen.h"
#include <valgrind/memcheck.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Keep the complete witness secret until validation has returned. */
static int validate(uint8_t sk[SYDO_SK_BYTES], int expected) {
    VALGRIND_MAKE_MEM_UNDEFINED(sk + SYDO_SK_WITNESS_OFFSET, SYDO_WITNESS_BYTES);
    int status = sydo_validate_secret_key(sk);
    VALGRIND_MAKE_MEM_DEFINED(&status, sizeof(status));
    VALGRIND_MAKE_MEM_DEFINED(sk + SYDO_SK_WITNESS_OFFSET, SYDO_WITNESS_BYTES);
    return status != expected;
}

int main(void) {
    if (!RUNNING_ON_VALGRIND) {
        fputs("Run this test under Valgrind Memcheck (make check-ct).\n", stderr);
        return 2;
    }
    uint8_t entropy[SYDO_KEYGEN_SEED_BYTES], pk[SYDO_PK_BYTES];
    uint8_t sk[SYDO_SK_BYTES], changed[SYDO_SK_BYTES];
    for (unsigned trial = 0; trial < 8; ++trial) {
        for (unsigned i = 0; i < sizeof(entropy); ++i)
            entropy[i] = trial == 0 ? 0 : trial == 1 ? 255 : (uint8_t)(13u + 97u*i + 61u*trial);
        if (sydo_keygen_from_seed(pk, sizeof(pk), sk, sizeof(sk), entropy, sizeof(entropy)) ||
            validate(sk, 0)) return 1;
    }

    /* Exercise every first-row encoding, including encodings outside the balls. */
    unsigned original = 0;
    for (unsigned bit = 0; bit < SYDO_RSD_INPUT_BITS; ++bit)
        original |= (unsigned)((sk[SYDO_SK_WITNESS_OFFSET + bit/8u] >> (bit%8u)) & 1u) << bit;
    for (unsigned value = 0; value < (1u << SYDO_RSD_INPUT_BITS); ++value) {
        memcpy(changed, sk, sizeof(sk));
        for (unsigned bit = 0; bit < SYDO_RSD_INPUT_BITS; ++bit) {
            uint8_t *byte = changed + SYDO_SK_WITNESS_OFFSET + bit/8u;
            unsigned mask = 1u << (bit%8u);
            *byte = (uint8_t)((*byte & ~mask) | (((value >> bit) & 1u) << (bit%8u)));
        }
        if (validate(changed, value == original ? 0 : -1)) return 1;
    }
    for (unsigned bit = SYDO_RSD_INPUT_BITS * SYDO_RSD_WEIGHT; bit < 8u * SYDO_WITNESS_BYTES; ++bit) {
        memcpy(changed, sk, sizeof(sk));
        changed[SYDO_SK_WITNESS_OFFSET + bit/8u] ^= (uint8_t)(1u << (bit%8u));
        if (validate(changed, -1)) return 1;
    }
    puts(SYDO_INSTANCE ": secret-key execution checks passed (8 keys, all first-row encodings and padding bits)");
    return 0;
}
