#include "profile.h"
#include "vole.h"
#include "prg.h"
#include "fields.h"
#include "bytes.h"
#include <string.h>

static inline void combine_pair(uint8_t *restrict column, uint8_t *restrict sum,
                                const uint8_t *restrict right) {
    for (size_t j = 0; j < SYDO_VOLE_STRIDE; ++j) {
        uint8_t value = right[j];
        column[j] ^= value;
        sum[j] ^= value;
    }
}

static void expand_row(const sydo_bavc *tree, const uint8_t iv[SYDO_SEED_BYTES], unsigned row,
                         unsigned missing, uint8_t total[SYDO_VOLE_STRIDE], uint8_t *columns) {
    uint8_t (*streams)[SYDO_VOLE_STRIDE] = tree->workspace->streams;
    sydo_prg_job jobs[64];
    memset(total, 0, SYDO_VOLE_STRIDE);
    memset(columns, 0, SYDO_DEPTH * SYDO_VOLE_STRIDE);
    for (unsigned start = 0; start < SYDO_LEAVES_PER_ROW; start += 64) {
        unsigned width = SYDO_LEAVES_PER_ROW - start < 64 ? SYDO_LEAVES_PER_ROW - start : 64;
        size_t count = 0;
        for (unsigned offset = 0; offset < width; ++offset) {
            unsigned leaf = start + offset;
            if (leaf == missing) { memset(streams[offset], 0, SYDO_VOLE_STRIDE); continue; }
            jobs[count].seed = tree->nodes + SYDO_SEED_BYTES * (SYDO_TREE_LEAVES - 1u + row * SYDO_LEAVES_PER_ROW + leaf);
            jobs[count].output = streams[offset];
            jobs[count++].tweak = UINT32_C(0x80000000) + row;
        }
        if (count) prg_batch(tree->workspace, jobs, count, iv, SYDO_VOLE_BYTES, SYDO_VOLE_BLOCK_OUTPUT_BYTES);
        /* BuildVOLE: collect right-child sums and combine adjacent pairs. */
        unsigned bit = 0;
        for (unsigned spacing = 1; spacing < width; spacing *= 2, ++bit)
            for (unsigned left = 0; left < width; left += 2 * spacing) {
                combine_pair(columns + bit * SYDO_VOLE_STRIDE, streams[left], streams[left + spacing]);
            }
        sydo_xor(total, streams[0], SYDO_VOLE_STRIDE);
        for (; bit < SYDO_DEPTH; ++bit)
            if ((start >> bit) & 1u) sydo_xor(columns + bit * SYDO_VOLE_STRIDE, streams[0], SYDO_VOLE_STRIDE);
    }
    if (missing < SYDO_LEAVES_PER_ROW)
        for (unsigned bit = 0; bit < SYDO_DEPTH; ++bit)
            if ((missing >> bit) & 1u) sydo_xor(columns + bit * SYDO_VOLE_STRIDE, total, SYDO_VOLE_STRIDE);
    sydo_wipe(streams, sizeof(tree->workspace->streams));
}

void vole_commit(const sydo_bavc *tree, const uint8_t iv[SYDO_SEED_BYTES], uint8_t u[SYDO_VOLE_BYTES],
                   uint8_t *columns, uint8_t *corrections) {
    SYDO_PROFILE_BEGIN(PROFILE_VOLE);
    uint8_t total[SYDO_VOLE_STRIDE];
    memset(columns, 0, SYDO_LAMBDA * SYDO_VOLE_STRIDE);
    for (unsigned row = 0; row < SYDO_TAU; ++row) {
        expand_row(tree, iv, row, SYDO_LEAVES_PER_ROW, total, columns + row * SYDO_DEPTH * SYDO_VOLE_STRIDE);
        if (!row) memcpy(u, total, SYDO_VOLE_BYTES);
        else {
            memcpy(corrections + (row - 1) * SYDO_VOLE_BYTES, total, SYDO_VOLE_BYTES);
            sydo_xor(corrections + (row - 1) * SYDO_VOLE_BYTES, u, SYDO_VOLE_BYTES);
        }
    }
    sydo_wipe(total, sizeof(total));
    SYDO_PROFILE_END(PROFILE_VOLE);
}

void vole_reconstruct(const sydo_bavc *tree, const uint8_t iv[SYDO_SEED_BYTES],
                        const uint8_t challenge[SYDO_SEED_BYTES], const uint8_t *corrections, uint8_t *columns) {
    SYDO_PROFILE_BEGIN(PROFILE_VOLE);
    uint8_t total[SYDO_VOLE_STRIDE];
    memset(columns, 0, SYDO_LAMBDA * SYDO_VOLE_STRIDE);
    for (unsigned row = 0; row < SYDO_TAU; ++row) {
        unsigned missing = bavc_index(challenge, row);
        uint8_t *block = columns + row * SYDO_DEPTH * SYDO_VOLE_STRIDE;
        expand_row(tree, iv, row, missing, total, block);
        if (row)
            for (unsigned bit = 0; bit < SYDO_DEPTH; ++bit)
                if ((missing >> bit) & 1u) sydo_xor(block + bit * SYDO_VOLE_STRIDE, corrections + (row - 1) * SYDO_VOLE_BYTES, SYDO_VOLE_BYTES);
    }
    sydo_wipe(total, sizeof(total));
    SYDO_PROFILE_END(PROFILE_VOLE);
}

enum { hash_coefficients = (SYDO_VOLE_CHECK_BYTES+SYDO_SEED_BYTES-1u)/SYDO_SEED_BYTES };

typedef struct {
    sydo_field matrix[4], s, square;
    uint64_t t;
} vole_hash_key;

typedef struct {
    sydo_field coefficients[hash_coefficients], h0, h2, h3;
    sydo_field_product pair;
    uint64_t acc;
    uint8_t bytes[SYDO_SEED_BYTES];
} vole_hash_workspace;

static void hash_column(uint8_t output[SYDO_VOLE_HASH_BYTES], const uint8_t column[SYDO_VOLE_BYTES],
                          const vole_hash_key *key, vole_hash_workspace *workspace) {
    for (unsigned i = 0; i < hash_coefficients; ++i) {
        unsigned offset = i*SYDO_SEED_BYTES;
        unsigned take = SYDO_VOLE_CHECK_BYTES-offset < SYDO_SEED_BYTES ? SYDO_VOLE_CHECK_BYTES-offset : SYDO_SEED_BYTES;
        if (take == SYDO_SEED_BYTES) workspace->coefficients[i] = field_read(column+offset);
        else {
            memset(workspace->bytes,0,sizeof(workspace->bytes));
            memcpy(workspace->bytes,column+offset,take);
            workspace->coefficients[i] = field_read(workspace->bytes);
        }
    }
    workspace->h0 = workspace->coefficients[0];
    for (unsigned i = 1; i < hash_coefficients; i += 2) {
        if (i+1u < hash_coefficients) {
            workspace->pair = field_product_add(field_product_mul(workspace->h0,key->square),
                field_product_mul(workspace->coefficients[i],key->s));
            workspace->h0 = field_add(field_product_reduce(workspace->pair),workspace->coefficients[i+1u]);
        } else workspace->h0 = field_add(field_mul(workspace->h0,key->s),workspace->coefficients[i]);
    }
    workspace->acc = workspace->coefficients[0].word[0];
    for (unsigned i = 0; i < hash_coefficients; ++i)
        for (unsigned word = i ? 0u : 1u; word < SYDO_FIELD_WORDS; ++word)
            workspace->acc = field64_mul(workspace->acc,key->t)^workspace->coefficients[i].word[word];
    workspace->h2 = field_add(field_mul(key->matrix[0],workspace->h0),field_mul64(key->matrix[1],workspace->acc));
    workspace->h3 = field_add(field_mul(key->matrix[2],workspace->h0),field_mul64(key->matrix[3],workspace->acc));
    field_write(output,workspace->h2);
    field_write(workspace->bytes,workspace->h3);
    memcpy(output+SYDO_SEED_BYTES,workspace->bytes,SYDO_VOLE_HASH_B_BYTES);
    sydo_xor(output,column+SYDO_VOLE_CHECK_BYTES,SYDO_VOLE_HASH_BYTES);
}

void vole_hash_batch(uint8_t *output, size_t output_stride, const uint8_t seed[SYDO_CHALLENGE1_BYTES],
                       const uint8_t *columns, size_t column_stride, size_t count) {
    SYDO_PROFILE_BEGIN(PROFILE_VOLE_CHECK);
    vole_hash_key key;
    for (unsigned i = 0; i < 4; ++i) key.matrix[i] = field_read(seed+i*SYDO_SEED_BYTES);
    key.s = field_read(seed+4u*SYDO_SEED_BYTES);
    key.square = field_mul(key.s,key.s);
    key.t = (uint64_t)sydo_load32(seed+5u*SYDO_SEED_BYTES) |
        ((uint64_t)sydo_load32(seed+5u*SYDO_SEED_BYTES+4u)<<32);
    vole_hash_workspace workspace;
    for (size_t i = 0; i < count; ++i)
        hash_column(output+i*output_stride,columns+i*column_stride,&key,&workspace);
    sydo_wipe(&workspace,sizeof(workspace));
    sydo_wipe(&key,sizeof(key));
    SYDO_PROFILE_END(PROFILE_VOLE_CHECK);
}

void vole_hash(uint8_t output[SYDO_VOLE_HASH_BYTES], const uint8_t seed[SYDO_CHALLENGE1_BYTES],
                 const uint8_t column[SYDO_VOLE_BYTES]) {
    vole_hash_batch(output,0,seed,column,0,1);
}
