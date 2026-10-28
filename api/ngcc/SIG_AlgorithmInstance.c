/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "sydo.h"
#include "parameters.h"
#include "bytes.h"

// DRNG_ctx for generating pseudorandom numbers within the SIG scheme
extern DRNG_ctx drng_algorithm;

// The following should be used to get pseudorandom numbers
// get_random_number(&drng_algorithm, random_number, random_number_len_bits);

unsigned long long sig_get_pk_len_bytes()
{
 return SYDO_PK_BYTES; 
}

unsigned long long sig_get_sk_len_bytes()
{
 return SYDO_SK_BYTES; 
}

unsigned long long sig_get_sn_len_bytes()
{
 return SYDO_SIG_BYTES; 
}

int sig_keygen(
	unsigned char *pk, unsigned long long *pk_len_bytes,
	unsigned char *sk, unsigned long long *sk_len_bytes)
{
    uint8_t seed[SYDO_KEYGEN_SEED_BYTES];
    if (!pk || !sk || !pk_len_bytes || !sk_len_bytes) return -1;
    int status = get_random_number(&drng_algorithm, seed, sizeof(seed) * 8u);
    if (status) { sydo_wipe(seed, sizeof(seed)); return -3; }
    status = sydo_keygen_from_seed(pk, SYDO_PK_BYTES, sk, SYDO_SK_BYTES, seed, sizeof(seed));
    sydo_wipe(seed, sizeof(seed));
    if (!status) { *pk_len_bytes = SYDO_PK_BYTES; *sk_len_bytes = SYDO_SK_BYTES; }
    return status;
}

int sig_sign(
	unsigned char *sk, unsigned long long sk_len_bytes,
	unsigned char *m, unsigned long long m_len_bytes,
	unsigned char *sn, unsigned long long *sn_len_bytes)
{
    uint8_t rho[SYDO_SEED_BYTES];
    if (!sn_len_bytes || sk_len_bytes != SYDO_SK_BYTES || m_len_bytes > SIZE_MAX ||
        (!m && m_len_bytes) || !sn || !sk) return -1;
    int status = get_random_number(&drng_algorithm, rho, sizeof(rho) * 8u);
    if (status) { sydo_wipe(rho, sizeof(rho)); return -3; }
    status = sydo_sign_from_seed(sn, SYDO_SIG_BYTES, m, (size_t)m_len_bytes,
                                               sk, (size_t)sk_len_bytes, rho, sizeof(rho));
    sydo_wipe(rho, sizeof(rho));
    if (!status) *sn_len_bytes = SYDO_SIG_BYTES;
    return status;
}

int sig_verify(
	unsigned char *pk, unsigned long long pk_len_bytes,
	unsigned char *sn, unsigned long long sn_len_bytes,
	unsigned char *m, unsigned long long m_len_bytes)
{
    if (pk_len_bytes != SYDO_PK_BYTES || sn_len_bytes != SYDO_SIG_BYTES || m_len_bytes > SIZE_MAX) return -1;
    return sydo_verify(sn, (size_t)sn_len_bytes, m, (size_t)m_len_bytes, pk, (size_t)pk_len_bytes);
}