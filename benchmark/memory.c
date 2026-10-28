#define _GNU_SOURCE
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "memory_alloc.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/resource.h>

DRNG_ctx drng_algorithm;
static uint8_t *pk, *sk, *signature;
static unsigned long long pk_bytes, sk_bytes, sig_bytes;
static uint8_t message[] = "SYndrome DecOding (SYDO) signature scheme";
static const char *operation;
static int status;
static sydo_memory_usage measured;

static void measure(void) {
    memory_start();
    if (!strcmp(operation, "keygen")) status = sig_keygen(pk, &pk_bytes, sk, &sk_bytes);
    else if (!strcmp(operation, "sign")) status = sig_sign(sk, sk_bytes, message, sizeof(message) - 1, signature, &sig_bytes);
    else status = sig_verify(pk, pk_bytes, signature, sig_bytes, message, sizeof(message) - 1);
    measured = memory_stop();
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[2], "stack") && strcmp(argv[2], "rss"))) {
        fprintf(stderr, "usage: %s keygen|sign|verify stack|rss\n", argv[0]); return 2;
    }
    operation = argv[1];
    if (strcmp(operation, "keygen") && strcmp(operation, "sign") && strcmp(operation, "verify")) return 2;
    uint8_t seed[64];
    for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)(0xa5u ^ i);
    pk_bytes = sig_get_pk_len_bytes(); sk_bytes = sig_get_sk_len_bytes(); sig_bytes = sig_get_sn_len_bytes();
    if (pk_bytes > SIZE_MAX || sk_bytes > SIZE_MAX || sig_bytes > SIZE_MAX) return 2;
    pk = malloc((size_t)pk_bytes); sk = malloc((size_t)sk_bytes); signature = malloc((size_t)sig_bytes);
    if (!pk || !sk || !signature || init_random_number(&drng_algorithm, seed, sizeof(seed))) return 2;
    if (sig_keygen(pk, &pk_bytes, sk, &sk_bytes)) return 1;
    if (!strcmp(operation, "verify") && sig_sign(sk, sk_bytes, message, sizeof(message) - 1, signature, &sig_bytes)) return 1;
    size_t stack_used = 0;
    if (!strcmp(argv[2], "stack")) {
        long page_value = sysconf(_SC_PAGESIZE);
        if (page_value <= 0) return 2;
        size_t page = (size_t)page_value, stack_size = 8u * 1024u * 1024u;
        uint8_t *mapping = mmap(NULL, stack_size + 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED || mprotect(mapping + page, stack_size, PROT_READ | PROT_WRITE)) return 2;
        uint8_t *stack = mapping + page;
        memset(stack, 0xa5, stack_size);
        ucontext_t caller, callee;
        if (getcontext(&callee)) return 2;
        callee.uc_stack.ss_sp = stack; callee.uc_stack.ss_size = stack_size; callee.uc_stack.ss_flags = 0;
        callee.uc_link = &caller;
        makecontext(&callee, measure, 0);
        if (swapcontext(&caller, &callee)) return 2;
        size_t untouched = 0;
        while (untouched < stack_size && stack[untouched] == 0xa5) ++untouched;
        stack_used = (stack_size - untouched + 255u) & ~(size_t)255u;
        if (munmap(mapping, stack_size + 2 * page)) return 2;
    } else measure();
    if (status || measured.overflow) { fprintf(stderr, "memory measurement failed: status=%d, overflow=%u\n", status, measured.overflow); return 1; }
    struct rusage resources;
    if (getrusage(RUSAGE_SELF, &resources)) return 2;
    printf("%s,%s,%zu,%zu,%zu,%zu,%zu,%ld\n", operation, argv[2], measured.requested_peak,
        measured.usable_peak, stack_used, measured.requested_live, measured.usable_live, resources.ru_maxrss);
    free(pk); free(sk); free(signature);
    return 0;
}
