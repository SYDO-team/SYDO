#include "sydo.h"
#include "parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compare_file(const char *directory, const char *extension,
                         const uint8_t *actual, size_t bytes) {
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/%s.%s", directory, SYDO_INSTANCE, extension) >= (int)sizeof(path)) return 1;
    FILE *file = fopen(path, "rb");
    if (!file) { perror(path); return 1; }
    int failed = 0;
    for (size_t i = 0; i < bytes; ++i)
        if (fgetc(file) != actual[i]) { fprintf(stderr, "%s differs at byte %zu\n", extension, i); failed = 1; break; }
    if (!failed && fgetc(file) != EOF) failed = 1;
    fclose(file);
    return failed;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s FIXTURE_DIRECTORY\n", argv[0]); return 2; }
    uint8_t entropy[SYDO_KEYGEN_SEED_BYTES], pk[SYDO_PK_BYTES], sk[SYDO_SK_BYTES];
    for (unsigned i = 0; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)(18 + 17 * i);
    if (sydo_keygen_from_seed(pk, sizeof(pk), sk, sizeof(sk), entropy, sizeof(entropy))) return 1;
    if (compare_file(argv[1], "pk", pk, sizeof(pk)) || compare_file(argv[1], "sk", sk, sizeof(sk))) return 1;
    if (sydo_keygen_from_seed(pk, sizeof(pk) - 1, sk, sizeof(sk), entropy, sizeof(entropy)) == 0) return 1;
    puts(SYDO_INSTANCE ": key fixtures verified; undersized buffer rejected");
    return 0;
}
