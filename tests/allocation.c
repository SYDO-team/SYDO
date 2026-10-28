#include "sydo.h"
#include "parameters.h"
#include "prg.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t allocations, fail_at, failures, workspaces, cleared;
static void *workspace;

static int fail_allocation(void) {
    if (++allocations == fail_at) { ++failures; return 1; }
    return 0;
}

void *sydo_test_malloc(size_t bytes) {
    if (fail_allocation()) return NULL;
    return malloc(bytes);
}

static void track_workspace(void *memory, size_t bytes) {
    if (memory && bytes == sizeof(sydo_prg_workspace)) {
        if (workspace || (uintptr_t)memory % _Alignof(sydo_prg_workspace)) abort();
        workspace = memory;
        ++workspaces;
    }
}

void *sydo_test_calloc(size_t count, size_t bytes) {
    if (fail_allocation()) return NULL;
    void *memory = calloc(count, bytes);
    track_workspace(memory,count*bytes);
    return memory;
}

void *sydo_test_aligned_alloc(size_t alignment, size_t bytes) {
    if (fail_allocation()) return NULL;
    void *memory = aligned_alloc(alignment,bytes);
    if (memory && (uintptr_t)memory % alignment) abort();
    track_workspace(memory,bytes);
    return memory;
}

void sydo_test_free(void *memory) {
    if (memory && memory == workspace) {
        const uint8_t *bytes = memory;
        for (size_t i = 0; i < sizeof(sydo_prg_workspace); ++i)
            if (bytes[i]) { fputs("workspace was released without clearing\n", stderr); abort(); }
        workspace = NULL;
        ++cleared;
    }
    free(memory);
}

static void reset(size_t failure) {
    if (workspace) abort();
    allocations = failures = workspaces = cleared = 0;
    fail_at = failure;
}

int main(void) {
    uint8_t pk[SYDO_PK_BYTES], sk[SYDO_SK_BYTES], entropy[SYDO_KEYGEN_SEED_BYTES];
    uint8_t signature[SYDO_SIG_BYTES], valid[SYDO_SIG_BYTES], rho[SYDO_SEED_BYTES];
    const uint8_t message[] = "SYDO workspace validation";
    for (unsigned i = 0; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)(18 + 17 * i);
    for (unsigned i = 0; i < sizeof(rho); ++i) rho[i] = (uint8_t)(32 + 17 * i);
    if (sydo_keygen_from_seed(pk, sizeof(pk), sk, sizeof(sk), entropy, sizeof(entropy))) return 1;
    unsigned cases = 0;
    for (unsigned verifier = 0; verifier < 2; ++verifier) {
        reset(0);
        int status = verifier ? sydo_verify(valid, sizeof(valid), message, sizeof(message) - 1, pk, sizeof(pk)) :
            sydo_sign_from_seed(signature, sizeof(signature), message, sizeof(message) - 1, sk, sizeof(sk), rho, sizeof(rho));
        if (status || workspace || workspaces != 1 || cleared != 1) return 1;
        size_t total = allocations;
        if (!verifier) memcpy(valid, signature, sizeof(valid));
        for (size_t failure = 1; failure <= total; ++failure) {
            if (failure > 24 && failure + 3 < total) continue;
            reset(failure);
            status = verifier ? sydo_verify(valid, sizeof(valid), message, sizeof(message) - 1, pk, sizeof(pk)) :
                sydo_sign_from_seed(signature, sizeof(signature), message, sizeof(message) - 1, sk, sizeof(sk), rho, sizeof(rho));
            if (status != -2 || failures != 1 || workspace || cleared != workspaces) {
                fprintf(stderr, "allocation failure handling: verifier=%u allocation=%zu\n", verifier, failure);
                return 1;
            }
            ++cases;
        }
    }
    printf("%s: %u allocation failures and workspace clearing before release verified\n", SYDO_INSTANCE, cases);
    return 0;
}
