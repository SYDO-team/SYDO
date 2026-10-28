#include "hash.h"
#include "bavc.h"
#include "bytes.h"
#include "auxfunc.h"
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "signature.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
DRNG_ctx drng_algorithm;
static unsigned xof_calls, random_calls, fail_xof_at;
int __real_pseudoXOF(unsigned long long,const unsigned char *,unsigned long long,unsigned char *);
int __wrap_pseudoXOF(unsigned long long n,const unsigned char *p,unsigned long long m,unsigned char *o) {
    if (++xof_calls == fail_xof_at) return -71;
    return __real_pseudoXOF(n,p,m,o);
}
int __real_get_random_number(DRNG_ctx *,unsigned char *,unsigned long long);
int __wrap_get_random_number(DRNG_ctx *d,unsigned char *p,unsigned long long n) {
    ++random_calls;return __real_get_random_number(d,p,n);
}
#define REQUIRE(c) do {if (!(c)) {fprintf(stderr,"NGCC direct-call check failed at line %u: %s\n",(unsigned)__LINE__,#c);return 1;}} while(0)
int main(void) {
    uint8_t input[129]={0},output[513];
    const unsigned lengths[]={0,1,65,129},sizes[]={0,20,40,64,513};
    for(unsigned a=0;a<sizeof(lengths)/sizeof(lengths[0]);++a)
        for(unsigned b=0;b<sizeof(sizes)/sizeof(sizes[0]);++b) {
            xof_calls=0;REQUIRE(sydo_xof(output,sizes[b],input,lengths[a])==0);REQUIRE(xof_calls==1);
        }
    sydo_hash_part parts[]={{input,65},{input+65,64}};
    xof_calls=0;REQUIRE(sydo_hash(output,64,9,parts,2)==0);REQUIRE(xof_calls==1);
    uint8_t challenge[SYDO_CHALLENGE2_BYTES]={0},check[SYDO_SEED_BYTES]={0},proof[SYDO_PROOF_BYTES]={0};
    sydo_grinding_hash grinding;uint8_t digest[SYDO_GRINDING_LANES][SYDO_SEED_BYTES];
    sydo_grinding_init(&grinding,challenge,check,proof);
    xof_calls=0;REQUIRE(sydo_grinding_hashes(digest,&grinding,7,0)==0);REQUIRE(xof_calls==0);
    xof_calls=0;REQUIRE(sydo_grinding_hashes(digest,&grinding,7,1)==0);REQUIRE(xof_calls==1);
    xof_calls=0;REQUIRE(sydo_grinding_hashes(digest,&grinding,7,SYDO_GRINDING_LANES+1u)==-1);REQUIRE(xof_calls==0);
    sydo_bavc tree={0};uint8_t root[SYDO_SEED_BYTES]={0},iv[SYDO_SEED_BYTES]={0},commitment[SYDO_COMMITMENT_BYTES];
    xof_calls=0;REQUIRE(bavc_commit(&tree,commitment,root,iv)==0);REQUIRE(xof_calls==SYDO_TAU+1u);bavc_clear(&tree);
    uint8_t seed[48]={0};REQUIRE(init_random_number(&drng_algorithm,seed,sizeof(seed))==0);
    unsigned long long pk_bytes=sig_get_pk_len_bytes(),sk_bytes=sig_get_sk_len_bytes(),sn_bytes=sig_get_sn_len_bytes();
    uint8_t *pk=malloc(pk_bytes),*sk=malloc(sk_bytes),*sn=malloc(sn_bytes);REQUIRE(pk&&sk&&sn);
    random_calls=0;REQUIRE(sig_keygen(pk,&pk_bytes,sk,&sk_bytes)==0);REQUIRE(random_calls==1);
    DRNG_ctx saved = drng_algorithm;
    random_calls=xof_calls=0;REQUIRE(sig_sign(sk,sk_bytes,input,3,sn,&sn_bytes)==0);REQUIRE(random_calls==1);
    unsigned sign_calls=xof_calls;
    random_calls=xof_calls=0;REQUIRE(sig_verify(pk,pk_bytes,sn,sn_bytes,input,3)==0);REQUIRE(random_calls==0);
    unsigned verify_calls=xof_calls;
    for (unsigned failure=1;failure<=verify_calls;++failure) {
        xof_calls=0;fail_xof_at=failure;
        REQUIRE(sig_verify(pk,pk_bytes,sn,sn_bytes,input,3)==-2);
        REQUIRE(xof_calls==failure);
    }
    fail_xof_at=0;
    REQUIRE(sig_verify(pk,pk_bytes,sn,sn_bytes,input,3)==0);
    sn[SIGNATURE_OPENING]^=1;
    REQUIRE(sig_verify(pk,pk_bytes,sn,sn_bytes,input,3)==-1);
    sn[SIGNATURE_OPENING]^=1;
    uint8_t *failed=malloc(sn_bytes);REQUIRE(failed);
    for (unsigned failure=1;failure<=sign_calls;++failure) {
        if (failure>3 && failure!=sign_calls) continue;
        drng_algorithm=saved;xof_calls=0;fail_xof_at=failure;
        memset(failed,0xa5,sn_bytes);
        REQUIRE(sig_sign(sk,sk_bytes,input,3,failed,&sn_bytes)==-2);
        REQUIRE(xof_calls==failure);
        for (size_t i=0;i<sn_bytes;++i) REQUIRE(failed[i]==0);
    }
    fail_xof_at=0;free(failed);
    sydo_wipe(sk,sk_bytes);free(pk);free(sk);free(sn);
    puts("NGCC direct calls, internal errors, invalid signatures and signing cleanup verified");
    return 0;
}
