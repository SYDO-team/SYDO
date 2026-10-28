#include "profile.h"
#include "bavc.h"
#include "prg.h"
#include "hash.h"
#include "bytes.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

unsigned bavc_index(const uint8_t challenge[SYDO_SEED_BYTES], unsigned row) {
    unsigned index = 0;
    for (unsigned bit = 0; bit < SYDO_DEPTH; ++bit)
        index |= sydo_bit(challenge, row * SYDO_DEPTH + bit) << bit;
    return index;
}

static size_t leaf_node(unsigned row, unsigned leaf) {
    return SYDO_TREE_LEAVES - 1u + SYDO_TAU * leaf + row;
}

static size_t commitment_offset(void) {
    size_t bytes = SYDO_TREE_NODES * SYDO_SEED_BYTES;
    size_t alignment = _Alignof(max_align_t);
    return (bytes + alignment - 1u) / alignment * alignment;
}

static size_t storage_bytes(void) {
    size_t bytes = commitment_offset() + SYDO_LEAVES_PER_ROW * SYDO_COMMITMENT_BYTES + 1u;
    size_t alignment = _Alignof(sydo_prg_workspace);
    return (bytes + alignment - 1u) / alignment * alignment;
}

static int allocate(sydo_bavc *state) {
    size_t bytes = storage_bytes();
    size_t alignment = _Alignof(sydo_prg_workspace);
    state->allocation = calloc(bytes + alignment - 1u, 1);
    size_t padding = state->allocation ? (alignment - (uintptr_t)state->allocation % alignment) % alignment : 0;
    state->nodes = state->allocation ? state->allocation + padding : NULL;
    state->commitments = state->nodes ? state->nodes + commitment_offset() : NULL;
    state->workspace = aligned_alloc(_Alignof(sydo_prg_workspace), sizeof(*state->workspace));
    if (state->workspace) memset(state->workspace,0,sizeof(*state->workspace));
    if (!state->nodes || !state->workspace) { bavc_clear(state); return -2; }
    return 0;
}

void bavc_clear_workspace(sydo_bavc *state) {
    if (state->workspace) { sydo_wipe(state->workspace, sizeof(*state->workspace)); free(state->workspace); }
    state->workspace = NULL;
}

void bavc_clear(sydo_bavc *state) {
    if (state->allocation) {
        sydo_wipe(state->allocation, storage_bytes() + _Alignof(sydo_prg_workspace) - 1u);
        free(state->allocation);
    }
    bavc_clear_workspace(state);
    state->allocation = state->nodes = state->commitments = NULL;
    sydo_wipe(state->iv, sizeof(state->iv));
}

static void expand_nodes(sydo_bavc *state, const uint8_t iv[SYDO_SEED_BYTES], const uint8_t *hidden) {
    SYDO_PROFILE_BEGIN(PROFILE_TREE);
    sydo_prg_job jobs[SYDO_CIPHER_LANES];
    for (size_t level = 0; level < SYDO_TREE_LEAVES - 1u;) {
        size_t end = 2 * level + 1;
        if (end > SYDO_TREE_LEAVES - 1u) end = SYDO_TREE_LEAVES - 1u;
        size_t pending = 0;
        for (size_t node = level; node < end; ++node) {
            if (hidden && hidden[node]) continue;
            jobs[pending].seed = state->nodes + SYDO_SEED_BYTES * node;
            jobs[pending].output = state->nodes + SYDO_SEED_BYTES * (2 * node + 1);
            jobs[pending++].tweak = (uint32_t)node;
            if (pending == SYDO_CIPHER_LANES) { prg_batch(state->workspace, jobs, pending, iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES); pending = 0; }
        }
        if (pending) prg_batch(state->workspace, jobs, pending, iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES);
        level = end;
    }
    SYDO_PROFILE_END(PROFILE_TREE);
}

static int transpose_leaves(sydo_bavc *state) {
    size_t bytes = (SYDO_TREE_LEAVES + 7u) / 8u;
    unsigned allocated = bytes > sizeof(state->workspace->streams);
    uint8_t *visited = allocated ? calloc(bytes, 1) : (uint8_t *)(void *)state->workspace->streams;
    if (!visited) return -2;
    if (!allocated) memset(visited, 0, bytes);
    uint8_t seed[SYDO_SEED_BYTES], displaced[SYDO_SEED_BYTES];
    uint8_t *leaves = state->nodes + (SYDO_TREE_LEAVES - 1u) * SYDO_SEED_BYTES;
    for (size_t start = 0; start < SYDO_TREE_LEAVES; ++start) {
        if (visited[start / 8u] & (1u << (start % 8u))) continue;
        size_t position = start;
        memcpy(seed, leaves + position * SYDO_SEED_BYTES, SYDO_SEED_BYTES);
        do {
            size_t next = (position % SYDO_TAU) * SYDO_LEAVES_PER_ROW + position / SYDO_TAU;
            memcpy(displaced, leaves + next * SYDO_SEED_BYTES, SYDO_SEED_BYTES);
            memcpy(leaves + next * SYDO_SEED_BYTES, seed, SYDO_SEED_BYTES);
            memcpy(seed, displaced, SYDO_SEED_BYTES);
            visited[position / 8u] |= (uint8_t)(1u << (position % 8u));
            position = next;
        } while (position != start);
    }
    sydo_wipe(seed, sizeof(seed));
    sydo_wipe(displaced, sizeof(displaced));
    if (allocated) free(visited);
    else memset(visited, 0, bytes);
    return 0;
}

static const uint8_t *node_seed(const sydo_bavc *state, size_t node) {
    if (node >= SYDO_TREE_LEAVES - 1u) {
        size_t leaf = node - (SYDO_TREE_LEAVES - 1u);
        node = SYDO_TREE_LEAVES - 1u + (leaf % SYDO_TAU) * SYDO_LEAVES_PER_ROW + leaf / SYDO_TAU;
    }
    return state->nodes + node * SYDO_SEED_BYTES;
}

static int commit_leaves(sydo_bavc *state, uint8_t digest[SYDO_COMMITMENT_BYTES],
                         const uint8_t iv[SYDO_SEED_BYTES], const uint8_t *challenge,
                         const uint8_t *opening) {
    SYDO_PROFILE_BEGIN(PROFILE_LEAF);
    sydo_prg_job jobs[SYDO_CIPHER_LANES];
    uint8_t rows[SYDO_TAU * SYDO_COMMITMENT_BYTES + 1u];
    const size_t length = SYDO_LEAVES_PER_ROW * SYDO_COMMITMENT_BYTES;
    for (unsigned row = 0; row < SYDO_TAU; ++row) {
        unsigned missing = challenge ? bavc_index(challenge, row) : SYDO_LEAVES_PER_ROW;
        size_t pending = 0;
        if (challenge)
            memcpy(state->commitments + SYDO_COMMITMENT_BYTES * missing,
                   opening + SYDO_COMMITMENT_BYTES * row, SYDO_COMMITMENT_BYTES);
        for (unsigned leaf = 0; leaf < SYDO_LEAVES_PER_ROW; ++leaf) {
            if (leaf == missing) continue;
            jobs[pending].seed = state->nodes + SYDO_SEED_BYTES * leaf_node(row, leaf);
            jobs[pending].output = state->commitments + SYDO_COMMITMENT_BYTES * leaf;
            jobs[pending++].tweak = row + SYDO_TREE_LEAVES - 1;
            if (pending == SYDO_CIPHER_LANES) { prg_batch(state->workspace, jobs, pending, iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES); pending = 0; }
        }
        if (pending) prg_batch(state->workspace, jobs, pending, iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES);
        state->commitments[length] = 1;
        SYDO_PROFILE_BEGIN(PROFILE_COMMITMENT_HASH);
        int status = sydo_xof(rows + SYDO_COMMITMENT_BYTES * row, SYDO_COMMITMENT_BYTES,
                              state->commitments, length + 1u);
        SYDO_PROFILE_END(PROFILE_COMMITMENT_HASH);
        if (status) { SYDO_PROFILE_END(PROFILE_LEAF); return status; }
    }
    int status = transpose_leaves(state);
    SYDO_PROFILE_END(PROFILE_LEAF);
    if (status) return status;
    rows[SYDO_TAU * SYDO_COMMITMENT_BYTES] = 1;
    SYDO_PROFILE_BEGIN(PROFILE_COMMITMENT_HASH);
    status = sydo_xof(digest, SYDO_COMMITMENT_BYTES, rows, sizeof(rows));
    SYDO_PROFILE_END(PROFILE_COMMITMENT_HASH);
    return status;
}

int bavc_commit(sydo_bavc *state, uint8_t digest[SYDO_COMMITMENT_BYTES], const uint8_t root[SYDO_SEED_BYTES], const uint8_t iv[SYDO_SEED_BYTES]) {
    if (allocate(state)) return -2;
    memcpy(state->iv, iv, SYDO_SEED_BYTES);
    memcpy(state->nodes, root, SYDO_SEED_BYTES);
    expand_nodes(state, iv, NULL);
    int status = commit_leaves(state, digest, iv, NULL, NULL);
    if (status) bavc_clear(state);
    return status;
}

static size_t hidden_paths(uint8_t *hidden, const uint8_t challenge[SYDO_SEED_BYTES]) {
    size_t internal = 0;
    for (unsigned row = 0; row < SYDO_TAU; ++row) {
        size_t node = leaf_node(row, bavc_index(challenge, row));
        hidden[node] = 1;
        node = (node - 1u) / 2u;
        while (!hidden[node]) {
            hidden[node] = 1;
            ++internal;
            if (!node) break;
            node = (node - 1u) / 2u;
        }
    }
    /* A hidden subtree with I internal nodes and tau leaves has I - tau + 1 boundary nodes. */
    return internal - SYDO_TAU + 1u;
}

int bavc_open(const sydo_bavc *state, uint8_t *opening, const uint8_t challenge[SYDO_SEED_BYTES]) {
    uint8_t *hidden = calloc(SYDO_TREE_NODES, 1);
    if (!hidden) return -2;
    SYDO_PROFILE_BEGIN(PROFILE_OPEN);
    size_t count = hidden_paths(hidden, challenge);
    if (count > SYDO_OPEN_NODES) { free(hidden); SYDO_PROFILE_END(PROFILE_OPEN); return 1; }
    sydo_prg_workspace *workspace = state->workspace;
    if (!workspace) {
        workspace = aligned_alloc(_Alignof(sydo_prg_workspace), sizeof(*workspace));
        if (!workspace) { free(hidden); SYDO_PROFILE_END(PROFILE_OPEN); return -2; }
        memset(workspace, 0, sizeof(*workspace));
    }
    sydo_prg_job jobs[SYDO_CIPHER_LANES];
    size_t pending = 0;
    for (unsigned row = 0; row < SYDO_TAU; ++row) {
        jobs[pending].seed = node_seed(state, leaf_node(row, bavc_index(challenge, row)));
        jobs[pending].output = opening + SYDO_COMMITMENT_BYTES * row;
        jobs[pending++].tweak = row + SYDO_TREE_LEAVES - 1;
        if (pending == SYDO_CIPHER_LANES) { prg_batch(workspace, jobs, pending, state->iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES); pending = 0; }
    }
    if (pending) prg_batch(workspace, jobs, pending, state->iv, SYDO_COMMITMENT_BYTES, SYDO_SEED_BYTES);
    if (workspace != state->workspace) {
        sydo_wipe(workspace, sizeof(*workspace));
        free(workspace);
    }
    size_t offset = SYDO_TAU * SYDO_COMMITMENT_BYTES;
    for (size_t end = SYDO_TREE_LEAVES - 1u; end > 0; --end) {
        size_t node = end - 1;
        unsigned left = hidden[2 * node + 1], right = hidden[2 * node + 2];
        if (left != right) {
            size_t sibling = 2 * node + 1 + left;
            memcpy(opening + offset, node_seed(state, sibling), SYDO_SEED_BYTES);
            offset += SYDO_SEED_BYTES;
        }
    }
    memset(opening + offset, 0, SYDO_OPEN_BYTES - offset);
    free(hidden);
    SYDO_PROFILE_END(PROFILE_OPEN);
    return 0;
}

int bavc_reconstruct(sydo_bavc *state, uint8_t digest[SYDO_COMMITMENT_BYTES], const uint8_t *opening,
                       const uint8_t challenge[SYDO_SEED_BYTES], const uint8_t iv[SYDO_SEED_BYTES]) {
    if (allocate(state)) return -2;
    memcpy(state->iv, iv, SYDO_SEED_BYTES);
    uint8_t *hidden = calloc(SYDO_TREE_NODES, 1);
    if (!hidden) { bavc_clear(state); return -2; }
    SYDO_PROFILE_BEGIN(PROFILE_RECONSTRUCT);
    hidden_paths(hidden, challenge);
    size_t offset = SYDO_TAU * SYDO_COMMITMENT_BYTES;
    int status = -1;
    for (size_t end = SYDO_TREE_LEAVES - 1u; end > 0; --end) {
        size_t node = end - 1;
        unsigned left = hidden[2 * node + 1], right = hidden[2 * node + 2];
        if (left != right) {
            if (offset + SYDO_SEED_BYTES > SYDO_OPEN_BYTES) goto done;
            memcpy(state->nodes + SYDO_SEED_BYTES * (2 * node + 1 + left), opening + offset, SYDO_SEED_BYTES);
            offset += SYDO_SEED_BYTES;
        }
    }
    for (size_t i = offset; i < SYDO_OPEN_BYTES; ++i) if (opening[i]) goto done;
    expand_nodes(state, iv, hidden);
    status = commit_leaves(state, digest, iv, challenge, opening);
done:
    free(hidden);
    if (status) bavc_clear(state);
    SYDO_PROFILE_END(PROFILE_RECONSTRUCT);
    return status;
}
