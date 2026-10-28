#ifndef SYDO_H
#define SYDO_H

#include <stddef.h>
#include <stdint.h>

size_t sydo_public_key_bytes(void);
size_t sydo_secret_key_bytes(void);
size_t sydo_signature_bytes(void);

/* Explicit entropy inputs make the core independent of the caller's RNG. */
int sydo_keygen_from_seed(uint8_t *pk, size_t pk_capacity,
                          uint8_t *sk, size_t sk_capacity,
                          const uint8_t *entropy, size_t entropy_bytes);
int sydo_sign_from_seed(uint8_t *signature, size_t signature_capacity,
                        const uint8_t *message, size_t message_bytes,
                        const uint8_t *sk, size_t sk_bytes,
                        const uint8_t *rho, size_t rho_bytes);
int sydo_verify(const uint8_t *signature, size_t signature_bytes,
                const uint8_t *message, size_t message_bytes,
                const uint8_t *pk, size_t pk_bytes);

#endif
