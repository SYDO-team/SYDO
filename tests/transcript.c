#include "sydo.h"
#include "parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int load(const char *directory, const char *extension, uint8_t *out, size_t size) {
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/%s.%s", directory, SYDO_INSTANCE, extension) >= (int)sizeof(path)) return 1;
    FILE *file = fopen(path, "rb");
    if (!file) return 1;
    int status = fread(out, 1, size, file) != size || fgetc(file) != EOF;
    fclose(file);
    return status;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s FIXTURE_DIRECTORY\n", argv[0]); return 2; }
    uint8_t pk[SYDO_PK_BYTES], sk[SYDO_SK_BYTES], rho[SYDO_SEED_BYTES];
    uint8_t *expected = malloc(SYDO_SIG_BYTES), *actual = malloc(SYDO_SIG_BYTES);
    const uint8_t message[] = "SYDO benchmark validation";
    if (!expected || !actual || load(argv[1], "pk", pk, sizeof(pk)) || load(argv[1], "sk", sk, sizeof(sk)) ||
        load(argv[1], "sig", expected, SYDO_SIG_BYTES)) return 2;
    for (unsigned i = 0; i < SYDO_SEED_BYTES; ++i) rho[i] = (uint8_t)(32 + 17 * i);
    if (sydo_sign_from_seed(actual, SYDO_SIG_BYTES, message, sizeof(message) - 1, sk, sizeof(sk), rho, sizeof(rho))) {
        fprintf(stderr, "sign failed\n"); return 1;
    }
    for (size_t i = 0; i < SYDO_SIG_BYTES; ++i)
        if (expected[i] != actual[i]) { fprintf(stderr, "signature differs at byte %zu: expected %02x, actual %02x\n", i, expected[i], actual[i]); return 1; }
    if (sydo_verify(expected, SYDO_SIG_BYTES, message, sizeof(message) - 1, pk, sizeof(pk))) { fprintf(stderr, "verify failed\n"); return 1; }
    if (!sydo_verify(expected, SYDO_SIG_BYTES, message, sizeof(message) - 2, pk, sizeof(pk))) return 1;
    if (!sydo_verify(expected, SYDO_SIG_BYTES - 1, message, sizeof(message) - 1, pk, sizeof(pk))) return 1;
    actual[SYDO_SIG_BYTES - 5] ^= 1;
    if (!sydo_verify(actual, SYDO_SIG_BYTES, message, sizeof(message) - 1, pk, sizeof(pk))) return 1;
    puts(SYDO_INSTANCE ": signature fixture, verification and negative cases passed");
    free(expected); free(actual);
    return 0;
}
