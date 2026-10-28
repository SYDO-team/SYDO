#include "cipher.h"
#include "bytes.h"
#include <string.h>

void cipher_clear(sydo_cipher_keys *expanded) {
    sydo_wipe(expanded->keys, expanded->lanes * sizeof(*expanded->keys));
    expanded->keys = NULL;
    expanded->lanes = 0;
    expanded->block_bytes = 0;
}
