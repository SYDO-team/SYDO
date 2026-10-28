#include "profile.h"
#include "sydo.h"
#include "signature.h"
#include "bavc.h"
#include "vole.h"
#include "rsd.h"
#include "hash.h"
#include "bytes.h"
#include <stdlib.h>
#include <string.h>

int sydo_verify(const uint8_t *signature, size_t signature_bytes,
                const uint8_t *message, size_t message_bytes,
                const uint8_t *pk, size_t pk_bytes) {
    if (!signature || signature_bytes != SYDO_SIG_BYTES || !pk || pk_bytes != SYDO_PK_BYTES || (!message && message_bytes)) return -1;
    const uint8_t *delta = signature + SIGNATURE_CHALLENGE;
    if (delta[SYDO_SEED_BYTES - 1u] & (uint8_t)(255u << (8 - SYDO_GRIND_BITS))) return -1;
    SYDO_PROFILE_BEGIN(PROFILE_VERIFY);
    sydo_bavc tree = {0};
    uint8_t mu[2u * SYDO_SEED_BYTES], iv[SYDO_SEED_BYTES], com[SYDO_COMMITMENT_BYTES], challenge1[SYDO_CHALLENGE1_BYTES], challenge2[SYDO_CHALLENGE2_BYTES], check[SYDO_SEED_BYTES], final[SYDO_SEED_BYTES];
    uint8_t *columns = malloc(SYDO_LAMBDA * SYDO_VOLE_STRIDE);
    uint8_t *transcript = malloc((SYDO_LAMBDA + 1u) * SYDO_VOLE_HASH_BYTES);
    int status = -2;
    if (!columns || !transcript) { status = -2; goto done; }
    sydo_hash_part digest_parts[] = {{pk, SYDO_PK_BYTES}, {message, message_bytes}};
    if (sydo_hash(mu, sizeof(mu), 8, digest_parts, 2)) goto done;
    sydo_hash_part iv_part = {signature + SIGNATURE_IV, SYDO_SEED_BYTES};
    if (sydo_hash(iv, SYDO_SEED_BYTES, 4, &iv_part, 1)) goto done;
    int reconstructed = bavc_reconstruct(&tree, com, signature + SIGNATURE_OPENING, delta, iv);
    if (reconstructed) { status = reconstructed == -1 ? -1 : -2; goto done; }
    vole_reconstruct(&tree, iv, delta, signature, columns);
    bavc_clear_workspace(&tree);
    sydo_hash_part first_parts[] = {{mu, sizeof(mu)}, {com, SYDO_COMMITMENT_BYTES}, {signature, SYDO_CORRECTIONS_BYTES}, {signature + SIGNATURE_IV, SYDO_SEED_BYTES}};
    if (sydo_hash(challenge1, SYDO_CHALLENGE1_BYTES, 9, first_parts, 4)) goto done;
    memcpy(transcript, signature + SIGNATURE_UHASH, SYDO_VOLE_HASH_BYTES);
    vole_hash_batch(transcript+SYDO_VOLE_HASH_BYTES,SYDO_VOLE_HASH_BYTES,challenge1,
        columns,SYDO_VOLE_STRIDE,SYDO_LAMBDA);
    for (unsigned i = 0; i < SYDO_LAMBDA; ++i) {
        uint8_t *hash = transcript + (i + 1u) * SYDO_VOLE_HASH_BYTES;
        uint8_t mask = (uint8_t)(0u - sydo_bit(delta, i));
        for (unsigned j = 0; j < SYDO_VOLE_HASH_BYTES; ++j) hash[j] ^= transcript[j] & mask;
    }
    sydo_hash_part second_parts[] = {{challenge1, SYDO_CHALLENGE1_BYTES}, {transcript, (SYDO_LAMBDA + 1u) * SYDO_VOLE_HASH_BYTES},
                                    {signature + SIGNATURE_WITNESS, SYDO_WITNESS_BYTES}};
    if (sydo_hash(challenge2, SYDO_CHALLENGE2_BYTES, 10, second_parts, 3)) goto done;
    if (rsd_verify(check, pk, signature + SIGNATURE_WITNESS, columns, challenge2, delta, signature + SIGNATURE_PROOF)) goto done;
    sydo_hash_part final_parts[] = {{challenge2, SYDO_CHALLENGE2_BYTES}, {check, SYDO_SEED_BYTES}, {signature + SIGNATURE_PROOF, SYDO_PROOF_BYTES}, {signature + SIGNATURE_COUNTER, 4}};
    if (sydo_hash(final, SYDO_SEED_BYTES, 11, final_parts, 4)) goto done;
    status = sydo_difference(final, delta, SYDO_SEED_BYTES) ? -1 : 0;
done:
    bavc_clear(&tree);
    free(columns); free(transcript);
    SYDO_PROFILE_END(PROFILE_VERIFY);
    return status;
}
