#ifndef SYDO_COMPONENT_API_H
#define SYDO_COMPONENT_API_H

#include "parameters.h"
#include <stdint.h>

#ifdef SYDO_CIPHER_BLAKE2S
#define SYDO_MATRIX_EXPAND_NAME "blake2s_expand"
#define SYDO_MATRIX_ENCRYPT_NAME "blake2s_encrypt"
#define SYDO_CIPHER_EXPAND_NAME SYDO_MATRIX_EXPAND_NAME
#define SYDO_CIPHER_ENCRYPT_NAME SYDO_MATRIX_ENCRYPT_NAME
#elif SYDO_CIPHER_KEY_BYTES == 24u
#define SYDO_MATRIX_EXPAND_NAME "aes192_expand"
#define SYDO_MATRIX_ENCRYPT_NAME "aes192_encrypt"
#define SYDO_CIPHER_EXPAND_NAME "rijndael192_expand"
#define SYDO_CIPHER_ENCRYPT_NAME "rijndael192_encrypt"
#else
#define SYDO_MATRIX_EXPAND_NAME "aes256_expand"
#define SYDO_MATRIX_ENCRYPT_NAME "aes256_encrypt"
#define SYDO_CIPHER_EXPAND_NAME "rijndael256_expand"
#define SYDO_CIPHER_ENCRYPT_NAME "rijndael256_encrypt"
#endif

void *component_setup(const char *name);
unsigned component_work_items(const char *name);
void component_evaluate(void *context, const char *name);
uint64_t component_checksum(void *context, const char *name);
void component_teardown(void *context);

#endif
