#include "component_api.h"
#include "cipher.h"
#include "fields.h"
#include "prg.h"
#include "bytes.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    sydo_cipher_keys schedule;
    _Alignas(64) sydo_cipher_round_keys round_keys[SYDO_CIPHER_BATCH_KEYS];
    sydo_prg_workspace workspace;
    _Alignas(64) uint8_t keys[64][SYDO_CIPHER_KEY_BYTES], input[64][SYDO_CIPHER_BLOCK_BYTES], output[64][SYDO_CIPHER_BLOCK_BYTES];
    _Alignas(64) uint8_t seeds[32][SYDO_SEED_BYTES], children[32][SYDO_COMMITMENT_BYTES], iv[SYDO_SEED_BYTES];
    sydo_prg_job jobs[32];
    _Alignas(64) sydo_field a, b;
} context;

unsigned component_work_items(const char *name) {
    if (!strcmp(name, "field_mul")) return 4096;
    if (!strcmp(name, SYDO_MATRIX_ENCRYPT_NAME) || !strcmp(name, SYDO_CIPHER_ENCRYPT_NAME)) return 16 * 64;
    if (!strcmp(name, SYDO_MATRIX_EXPAND_NAME) || !strcmp(name, SYDO_CIPHER_EXPAND_NAME)) return 8 * 64;
    if (!strcmp(name, "tree_prg")) return 8 * 32;
    return 0;
}

void *component_setup(const char *name) {
    if (!component_work_items(name)) return NULL;
    context *c = aligned_alloc(_Alignof(context),sizeof(context));
    if (!c) return NULL;
    memset(c,0,sizeof(*c));
    for (unsigned i = 0; i < 64; ++i)
        for (unsigned j = 0; j < SYDO_CIPHER_KEY_BYTES; ++j) {
            c->keys[i][j] = (uint8_t)(17 * i + 3 * j);
            c->input[i][j] = (uint8_t)(11 * i + 7 * j);
        }
    uint8_t a[SYDO_SEED_BYTES], b[SYDO_SEED_BYTES];
    for (unsigned i = 0; i < SYDO_SEED_BYTES; ++i) { a[i] = (uint8_t)(13 + 17 * i); b[i] = (uint8_t)(31 + 7 * i); c->iv[i] = (uint8_t)(128 + i); }
    c->a = field_read(a); c->b = field_read(b);
    for (unsigned i = 0; i < 32; ++i) {
        memcpy(c->seeds[i], c->keys[i], SYDO_SEED_BYTES);
        c->jobs[i] = (sydo_prg_job){c->seeds[i], c->children[i], i};
    }
    cipher_expand(&c->schedule, c->round_keys, c->keys[0], SYDO_CIPHER_KEY_BYTES, 64, !strncmp(name, "aes", 3) ? SYDO_MATRIX_BLOCK_BYTES : SYDO_CIPHER_BLOCK_BYTES);
    return c;
}

void component_evaluate(void *opaque, const char *name) {
    context *c = opaque;
    if (!strcmp(name, "field_mul")) {
        sydo_field a = c->a, b = c->b;
        for (unsigned i = 0; i < 4096; ++i) a = field_mul(a, b);
        c->a = a;
    } else if (!strcmp(name, "tree_prg")) {
        for (unsigned i = 0; i < 8; ++i) { c->iv[0] ^= (uint8_t)i; prg_batch(&c->workspace, c->jobs, 32, c->iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES); }
    } else if (strstr(name, "expand")) {
        for (unsigned i = 0; i < 8; ++i) {
            c->keys[0][0] ^= (uint8_t)i;
            cipher_expand(&c->schedule, c->round_keys, c->keys[0], SYDO_CIPHER_KEY_BYTES, 64, !strncmp(name, "aes", 3) ? SYDO_MATRIX_BLOCK_BYTES : SYDO_CIPHER_BLOCK_BYTES);
        }
    } else {
        for (unsigned i = 0; i < 16; ++i) {
            c->input[0][0] ^= (uint8_t)i;
            cipher_encrypt(&c->schedule, c->input[0], SYDO_CIPHER_BLOCK_BYTES, c->output[0], SYDO_CIPHER_BLOCK_BYTES, 64);
        }
    }
}

uint64_t component_checksum(void *opaque, const char *name) {
    context *c = opaque;
    if (strstr(name, "expand")) cipher_encrypt(&c->schedule, c->input[0], SYDO_CIPHER_BLOCK_BYTES, c->output[0], SYDO_CIPHER_BLOCK_BYTES, 64);
    uint8_t field[SYDO_SEED_BYTES];
    field_write(field, c->a);
    const uint8_t *bytes = !strcmp(name, "field_mul") ? field :
        (!strcmp(name, "tree_prg") ? c->children[0] : c->output[0]);
    size_t count = !strcmp(name, "field_mul") ? SYDO_SEED_BYTES : (!strcmp(name, "tree_prg") ? sizeof(c->children) : sizeof(c->output));
    uint64_t result = 0;
    for (size_t i = 0; i < count; ++i) result = (result * 257u) ^ bytes[i];
    return result;
}

void component_teardown(void *opaque) {
    context *c = opaque;
    cipher_clear(&c->schedule);
    sydo_wipe(c, sizeof(*c));
    free(c);
}
