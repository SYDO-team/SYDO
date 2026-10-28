#include "profile.h"
#include "sydo.h"
#include "keygen.h"
#include "signature.h"
#include "bavc.h"
#include "vole.h"
#include "rsd.h"
#include "hash.h"
#include "bytes.h"
#include <stdlib.h>
#include <string.h>

int sydo_sign_from_seed(uint8_t *signature, size_t signature_capacity,
                        const uint8_t *message, size_t message_bytes,
                        const uint8_t *sk, size_t sk_bytes,
                        const uint8_t *rho, size_t rho_bytes) {
    if (!signature || signature_capacity < SYDO_SIG_BYTES || !sk || sk_bytes != SYDO_SK_BYTES ||
        (!message && message_bytes) || !rho || rho_bytes != SYDO_SEED_BYTES) return -1;
    SYDO_PROFILE_BEGIN(PROFILE_SIGN);
    int status = sydo_validate_secret_key(sk);
    if (status) { SYDO_PROFILE_END(PROFILE_SIGN); return status; }

    sydo_bavc tree = {0};
    sydo_grinding_hash grinding_hash;
    uint8_t candidates[SYDO_GRINDING_LANES][SYDO_SEED_BYTES];
    uint8_t mu[2u * SYDO_SEED_BYTES], root_iv[2u * SYDO_SEED_BYTES], iv[SYDO_SEED_BYTES], com[SYDO_COMMITMENT_BYTES], u[SYDO_VOLE_BYTES], challenge1[SYDO_CHALLENGE1_BYTES], challenge2[SYDO_CHALLENGE2_BYTES], check[SYDO_SEED_BYTES];
    uint8_t *columns = malloc(SYDO_LAMBDA * SYDO_VOLE_STRIDE);
    uint8_t *transcript = malloc((SYDO_LAMBDA + 1u) * SYDO_VOLE_HASH_BYTES);
    status = -2;
    if (!columns || !transcript) goto done;
    sydo_hash_part digest_parts[] = {{sk, SYDO_PK_BYTES}, {message, message_bytes}};
    if (sydo_hash(mu, sizeof(mu), 8, digest_parts, 2)) goto done;
    sydo_hash_part seed_parts[] = {{sk + SYDO_PK_BYTES, SYDO_SEED_BYTES}, {mu, sizeof(mu)}, {rho, SYDO_SEED_BYTES}};
    if (sydo_hash(root_iv, sizeof(root_iv), 3, seed_parts, 3)) goto done;
    sydo_hash_part iv_part = {root_iv + SYDO_SEED_BYTES, SYDO_SEED_BYTES};
    if (sydo_hash(iv, SYDO_SEED_BYTES, 4, &iv_part, 1)) goto done;
    if (bavc_commit(&tree, com, root_iv, iv)) goto done;
    vole_commit(&tree, iv, u, columns, signature);
    sydo_hash_part first_parts[] = {{mu, sizeof(mu)}, {com, SYDO_COMMITMENT_BYTES}, {signature, SYDO_CORRECTIONS_BYTES}, {root_iv + SYDO_SEED_BYTES, SYDO_SEED_BYTES}};
    if (sydo_hash(challenge1, SYDO_CHALLENGE1_BYTES, 9, first_parts, 4)) goto done;
    vole_hash(transcript, challenge1, u);
    vole_hash_batch(transcript+SYDO_VOLE_HASH_BYTES,SYDO_VOLE_HASH_BYTES,challenge1,
        columns,SYDO_VOLE_STRIDE,SYDO_LAMBDA);
    memcpy(signature + SIGNATURE_UHASH, transcript, SYDO_VOLE_HASH_BYTES);
    memcpy(signature + SIGNATURE_WITNESS, sk + SYDO_SK_WITNESS_OFFSET, SYDO_WITNESS_BYTES);
    sydo_xor(signature + SIGNATURE_WITNESS, u, SYDO_WITNESS_BYTES);
    sydo_hash_part second_parts[] = {{challenge1, SYDO_CHALLENGE1_BYTES}, {transcript, (SYDO_LAMBDA + 1u) * SYDO_VOLE_HASH_BYTES},
                                    {signature + SIGNATURE_WITNESS, SYDO_WITNESS_BYTES}};
    if (sydo_hash(challenge2, SYDO_CHALLENGE2_BYTES, 10, second_parts, 3)) goto done;
    if (rsd_prove(signature + SIGNATURE_PROOF, check, sk, sk + SYDO_SK_WITNESS_OFFSET, u, columns, challenge2)) goto done;
    status = -2;
    SYDO_PROFILE_BEGIN(PROFILE_GRIND);
    sydo_grinding_init(&grinding_hash, challenge2, check, signature + SIGNATURE_PROOF);
    for (uint64_t first = 0; first < (UINT64_C(1) << 32); first += SYDO_GRINDING_LANES) {
        unsigned count = (UINT64_C(1) << 32) - first < SYDO_GRINDING_LANES ?
            (unsigned)((UINT64_C(1) << 32) - first) : SYDO_GRINDING_LANES;
        if (sydo_grinding_hashes(candidates, &grinding_hash, (uint32_t)first, count)) { SYDO_PROFILE_END(PROFILE_GRIND); goto done; }
        for (unsigned lane = 0; lane < count; ++lane) {
            if (candidates[lane][SYDO_SEED_BYTES - 1u] & (uint8_t)(255u << (8 - SYDO_GRIND_BITS))) continue;
            memcpy(signature + SIGNATURE_CHALLENGE, candidates[lane], SYDO_SEED_BYTES);
            int opened = bavc_open(&tree, signature + SIGNATURE_OPENING, signature + SIGNATURE_CHALLENGE);
            if (opened < 0) { status = opened; SYDO_PROFILE_END(PROFILE_GRIND); goto done; }
            if (opened) continue;
            memcpy(signature + SIGNATURE_IV, root_iv + SYDO_SEED_BYTES, SYDO_SEED_BYTES);
            sydo_store32(signature + SIGNATURE_COUNTER, (uint32_t)(first + lane));
            status = 0;
            break;
        }
        if (!status) break;
    }
    SYDO_PROFILE_END(PROFILE_GRIND);
done:
    bavc_clear(&tree);
    if (columns) { sydo_wipe(columns, SYDO_LAMBDA * SYDO_VOLE_STRIDE); free(columns); }
    if (transcript) { sydo_wipe(transcript, (SYDO_LAMBDA + 1u) * SYDO_VOLE_HASH_BYTES); free(transcript); }
    sydo_wipe(&grinding_hash, sizeof(grinding_hash)); sydo_wipe(candidates, sizeof(candidates));
    sydo_wipe(u, sizeof(u)); sydo_wipe(root_iv, sizeof(root_iv)); sydo_wipe(check, sizeof(check));
    if (status) sydo_wipe(signature, SYDO_SIG_BYTES);
    SYDO_PROFILE_END(PROFILE_SIGN);
    return status;
}
