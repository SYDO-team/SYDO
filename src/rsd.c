#include "profile.h"
#include "rsd.h"
#include "fields.h"
#include "matrix.h"
#include "bytes.h"
#include <stdlib.h>
#include <string.h>

typedef struct { sydo_field c[SYDO_DEGREE]; } polynomial;
typedef struct { uint8_t upper, lower; } subset_pair;
typedef struct {
    sydo_public_matrix matrix;
    sydo_field monomials[SYDO_RSD_MASK_COUNT];
    sydo_field matrix_row[SYDO_RSD_BLOCK_LENGTH], coefficients[SYDO_RSD_SELECTOR_TERMS][SYDO_RSD_BALL_TERMS];
} rsd_workspace;

typedef struct { sydo_field h0[4], h1[4], s, t, xi0, xi1; } constraint_hash;

static sydo_field syndrome_element(const uint8_t *pk, unsigned index) {
    size_t offset = index * SYDO_SEED_BYTES;
    size_t remaining = SYDO_SYNDROME_BYTES - offset;
    if (remaining >= SYDO_SEED_BYTES) return field_read(pk + SYDO_SEED_BYTES + offset);
    uint8_t bytes[SYDO_SEED_BYTES] = {0};
    memcpy(bytes, pk + SYDO_SEED_BYTES + offset, remaining);
    return field_read(bytes);
}

static unsigned bit_count(unsigned mask) {
    unsigned count = 0;
    for (unsigned i = 0; i < SYDO_RSD_ETA_1; ++i) count += (mask >> i) & 1u;
    return count;
}

static void ball_masks(unsigned masks[SYDO_RSD_BALL_TERMS]) {
    unsigned rank = 0;
    for (unsigned degree = 0; degree <= SYDO_RSD_R_1; ++degree)
        for (unsigned value = 0; value < SYDO_RSD_MASK_COUNT; ++value)
            if (bit_count(value) == degree) {
                unsigned reversed = 0;
                for (unsigned bit = 0; bit < SYDO_RSD_ETA_1; ++bit) reversed |= ((value >> bit) & 1u) << (SYDO_RSD_ETA_1 - 1u - bit);
                masks[rank++] = reversed;
            }
}

static void row_values(sydo_field values[SYDO_RSD_INPUT_BITS], const uint8_t *columns, unsigned first) {
    memset(values, 0, SYDO_RSD_INPUT_BITS * sizeof(*values));
    uint64_t packed[2] = {0};
    for (unsigned byte = 0; byte < SYDO_SEED_BYTES; ++byte) {
        packed[0] = packed[1] = 0;
        for (unsigned j = 0; j < 8; ++j) {
            const uint8_t *p = columns + (8 * byte + j) * SYDO_VOLE_STRIDE + first / 8;
            unsigned word = ((unsigned)p[0] | (unsigned)p[1] << 8) >> (first % 8);
            packed[0] |= (uint64_t)(word & 255u) << (8 * j);
            packed[1] |= (uint64_t)(word >> 8) << (8 * j);
        }
        packed[0] = sydo_transpose8(packed[0]);
        packed[1] = sydo_transpose8(packed[1]);
        for (unsigned j = 0; j < SYDO_RSD_INPUT_BITS; ++j)
            values[j].word[byte / 8] |= (uint64_t)(uint8_t)(packed[j / 8] >> (8 * (j % 8))) << (8 * (byte % 8));
    }
    sydo_wipe(packed, sizeof(packed));
}

static sydo_field tail_value(const uint8_t *columns, unsigned block) {
    sydo_field value = field_zero();
    /* Swap the two sums in sum c[i,j] x^(i+j). */
    for (unsigned col = SYDO_LAMBDA; col-- > 0;)
        value = field_add(field_shift(value),
                          field_read(columns + col * SYDO_VOLE_STRIDE + SYDO_WITNESS_BYTES + block * SYDO_SEED_BYTES));
    return value;
}

static void multiply_linear(polynomial *result, const polynomial *a, unsigned degree,
                                    sydo_field constant, unsigned bit, int prover) {
    if (!prover) {
        result->c[0] = field_mul(a->c[0], constant);
        return;
    }
    for (unsigned i = 0; i <= degree; ++i) {
        sydo_field product = i == degree ? field_mask(constant, (unsigned)(a->c[i].word[0] & 1u))
                                          : field_mul(a->c[i], constant);
        result->c[i] = i ? field_add(product, field_mask(a->c[i - 1], bit)) : product;
    }
    /* Constraint hashing uses coefficients below degree SYDO_DEGREE. */
    if (degree + 1 < SYDO_DEGREE)
        result->c[degree + 1] = field_mask(a->c[degree], bit);
}

static void hash_init(constraint_hash *hash, const uint8_t challenge[SYDO_CHALLENGE2_BYTES]) {
    memset(hash, 0, sizeof(*hash));
    hash->xi0 = field_read(challenge);
    hash->xi1 = field_read(challenge + SYDO_SEED_BYTES);
    hash->s = field_read(challenge + 2 * SYDO_SEED_BYTES);
    for (unsigned i = 0; i < 8; ++i) hash->t.word[0] |= (uint64_t)challenge[3 * SYDO_SEED_BYTES + i] << (8 * i);
}

static void hash_constraint(constraint_hash *hash, const polynomial *value,
                              unsigned shift, int prover, const sydo_field powers[5]) {
    for (unsigned i = 0; i < (prover ? 4u : 1u); ++i) {
        sydo_field coefficient = field_zero();
        if (prover) {
            if (i >= shift) coefficient = value->c[i - shift];
        } else coefficient = shift ? field_mul(value->c[0], powers[shift]) : value->c[0];
        hash->h0[i] = field_add(field_mul(hash->h0[i], hash->s), coefficient);
        hash->h1[i] = field_add(field_mul64(hash->h1[i], hash->t.word[0]), coefficient);
    }
}

static void interpolate(sydo_field coefficients[SYDO_RSD_SELECTOR_TERMS][SYDO_RSD_BALL_TERMS], const sydo_field values[SYDO_RSD_BLOCK_LENGTH],
                          const subset_pair *pairs, const unsigned offsets[SYDO_RSD_ETA_1 + 1u]) {
    for (unsigned a = 0; a < SYDO_RSD_SELECTOR_TERMS; ++a)
        for (unsigned b = 0; b < SYDO_RSD_BALL_TERMS; ++b) coefficients[a][b] = values[SYDO_RSD_BALL_TERMS * a + b];
    for (unsigned bit = 0; bit < SYDO_RSD_ETA_1; ++bit)
        for (unsigned j = offsets[bit]; j < offsets[bit+1u]; ++j)
            for (unsigned a = 0; a < SYDO_RSD_SELECTOR_TERMS; ++a)
                coefficients[a][pairs[j].upper] = field_add(coefficients[a][pairs[j].upper],coefficients[a][pairs[j].lower]);
    for (unsigned b = 0; b < SYDO_RSD_BALL_TERMS; ++b) {
        coefficients[1][b] = field_add(coefficients[1][b], coefficients[0][b]);
        coefficients[2][b] = field_add(coefficients[2][b], coefficients[0][b]);
    }
}

static void shift_coefficients(sydo_field *restrict coefficients, const subset_pair *pairs,
                               const unsigned offsets[SYDO_RSD_ETA_1 + 1u], const unsigned bits[SYDO_RSD_INPUT_BITS]) {
    /* Substitute X[i] + b[i] in the multilinear polynomial. */
    for (unsigned bit = 0; bit < SYDO_RSD_ETA_1; ++bit)
        for (unsigned j = offsets[bit]; j < offsets[bit+1u]; ++j)
            coefficients[pairs[j].lower] = field_add(coefficients[pairs[j].lower],
                field_mask(coefficients[pairs[j].upper],bits[SYDO_RSD_ETA_0 + bit]));
}

static void row_monomials(sydo_field monomials[SYDO_RSD_MASK_COUNT], uint8_t products[SYDO_RSD_MASK_COUNT],
                           const sydo_field variables[SYDO_RSD_INPUT_BITS], const unsigned bits[SYDO_RSD_INPUT_BITS],
                           uint8_t masks[SYDO_DEGREE][SYDO_RSD_MONOMIALS_PER_DEGREE], const unsigned counts[SYDO_DEGREE],
                           const uint8_t selected_bit[SYDO_RSD_MASK_COUNT], int prover) {
    products[0] = 1;
    for (unsigned degree = 1; degree <= SYDO_DEGREE; ++degree)
        for (unsigned index = 0; index < counts[degree-1u]; ++index) {
            unsigned mask = masks[degree-1u][index], bit = selected_bit[mask];
            unsigned lower = mask ^ (1u << bit);
            monomials[mask] = degree == 1 ? variables[SYDO_RSD_ETA_0 + bit]
                : field_mul(monomials[lower],variables[SYDO_RSD_ETA_0 + bit]);
            if (prover) products[mask] = (uint8_t)(products[lower] & bits[SYDO_RSD_ETA_0 + bit]);
        }
}

static polynomial membership_polynomial(const sydo_field monomials[SYDO_RSD_MASK_COUNT], const uint8_t products[SYDO_RSD_MASK_COUNT],
                                          const uint8_t degrees[SYDO_RSD_MASK_COUNT], unsigned mask) {
    polynomial result = {{{{0}}}};
    result.c[0] = monomials[mask];
    /* Choose the constant factors; the remaining factors contribute witness bits. */
    for (unsigned subset = (mask-1u)&mask; subset; subset = (subset-1u)&mask) {
        unsigned degree = SYDO_DEGREE-degrees[subset];
        result.c[degree] = field_add(result.c[degree],field_mask(monomials[subset],products[mask^subset]));
    }
    return result;
}

static int constraints(polynomial *syndrome, constraint_hash *hash, const uint8_t pk[SYDO_PK_BYTES],
                          const uint8_t *witness, const uint8_t *columns,
                          const uint8_t challenge[SYDO_CHALLENGE2_BYTES], const sydo_field powers[5], int prover) {
    sydo_field alpha[SYDO_SYNDROME_FIELDS];
    rsd_workspace *workspace = calloc(1, sizeof(*workspace));
    if (!workspace) return -2;
    sydo_public_matrix *matrix = &workspace->matrix;
    sydo_field *monomials = workspace->monomials;
    sydo_field *matrix_row = workspace->matrix_row;
    sydo_field (*coefficients)[SYDO_RSD_BALL_TERMS] = workspace->coefficients;
    SYDO_PROFILE_BEGIN(prover ? PROFILE_PROVE : PROFILE_CONSTRAINT_VERIFY);
    unsigned masks[SYDO_RSD_BALL_TERMS], ends[5] = {0};
    uint8_t degrees[SYDO_RSD_MASK_COUNT], reversed[SYDO_RSD_MASK_COUNT], indices[SYDO_RSD_MASK_COUNT] = {0}, selected_bit[SYDO_RSD_MASK_COUNT];
    uint8_t monomial_masks[SYDO_DEGREE][SYDO_RSD_MONOMIALS_PER_DEGREE];
    unsigned monomial_counts[SYDO_DEGREE] = {0};
    for (unsigned value = 0; value < SYDO_RSD_MASK_COUNT; ++value) {
        degrees[value] = (uint8_t)bit_count(value);
        if (value && degrees[value] <= SYDO_DEGREE) {
            unsigned bit = 0;
            while (!(value & (1u << bit))) ++bit;
            selected_bit[value] = (uint8_t)bit;
            monomial_masks[degrees[value] - 1u][monomial_counts[degrees[value] - 1u]++] = (uint8_t)value;
        }
        unsigned reverse = 0;
        for (unsigned bit = 0; bit < SYDO_RSD_ETA_1; ++bit) reverse |= ((value >> bit) & 1u) << (SYDO_RSD_ETA_1 - 1u - bit);
        reversed[value] = (uint8_t)reverse;
    }
    ball_masks(masks);
    for (unsigned b = 0; b < SYDO_RSD_BALL_TERMS; ++b) {
        indices[masks[b]] = (uint8_t)b;
        ++ends[degrees[masks[b]]+1u];
    }
    for (unsigned degree = 1; degree < 5; ++degree) ends[degree] += ends[degree-1u];
    subset_pair pairs[SYDO_RSD_R_1 * SYDO_RSD_BALL_TERMS];
    unsigned offsets[SYDO_RSD_ETA_1 + 1u] = {0}, pair_count = 0;
    for (unsigned bit = 0; bit < SYDO_RSD_ETA_1; ++bit) {
        for (unsigned b = 0; b < SYDO_RSD_BALL_TERMS; ++b)
            if (masks[b] & (1u << bit))
                pairs[pair_count++] = (subset_pair){(uint8_t)b,indices[masks[b] ^ (1u << bit)]};
        offsets[bit+1u] = pair_count;
    }
    for (unsigned c = 0; c < SYDO_SYNDROME_FIELDS; ++c) alpha[c] = field_read(challenge + 3 * SYDO_SEED_BYTES + 8 + SYDO_SEED_BYTES * c);
    matrix_init(matrix, pk, alpha);
    memset(syndrome, 0, sizeof(*syndrome));
    monomials[0] = field_one();
    for (unsigned row = 0; row < SYDO_RSD_WEIGHT; ++row) {
        sydo_field variables[SYDO_RSD_INPUT_BITS];
        unsigned bits[SYDO_RSD_INPUT_BITS];
        row_values(variables, columns, SYDO_RSD_INPUT_BITS * row);
        for (unsigned j = 0; j < SYDO_RSD_INPUT_BITS; ++j) {
            bits[j] = sydo_bit(witness, SYDO_RSD_INPUT_BITS * row + j);
            if (!prover) variables[j] = field_add(variables[j], field_mask(powers[1], bits[j]));
        }
        uint8_t products[SYDO_RSD_MASK_COUNT] = {0};
        row_monomials(monomials,products,variables,bits,monomial_masks,monomial_counts,selected_bit,prover);
        polynomial first = {{{{0}}}};
        first.c[0] = variables[0];
        if (prover) first.c[1] = field_mask(field_one(), bits[0]);
        polynomial pair;
        multiply_linear(&pair, &first, 1, variables[1], bits[1], prover);
        hash_constraint(hash, &pair, 2, prover, powers);
        /* The canonical vector order is lexicographic in coordinates 0..7. */
        for (unsigned value = 0; value < SYDO_RSD_MASK_COUNT; ++value)
            if (degrees[value] == SYDO_DEGREE) {
                unsigned mask = reversed[value];
                polynomial membership = {{{{0}}}};
                if (prover) membership = membership_polynomial(monomials,products,degrees,mask);
                else membership.c[0] = monomials[mask];
                hash_constraint(hash, &membership, 0, prover, powers);
                sydo_wipe(&membership,sizeof(membership));
            }
        matrix_fold_row(matrix_row, matrix, row);
        interpolate(coefficients, matrix_row, pairs, offsets);
        for (unsigned a = 0; a < SYDO_RSD_SELECTOR_TERMS; ++a) {
            sydo_field_product group[4];
            sydo_field leading = field_zero(), value = field_zero();
            for (unsigned p = 0; p < 4; ++p) group[p] = field_product_zero();
            if (prover) {
                shift_coefficients(coefficients[a],pairs,offsets,bits);
                leading = coefficients[a][0];
                for (unsigned degree = 1; degree < SYDO_DEGREE; ++degree) {
                    sydo_field_product sum = field_product_zero();
                    for (unsigned b = ends[degree]; b < ends[degree+1u]; ++b)
                        sum = field_product_add(sum,field_product_mul(coefficients[a][b],monomials[masks[b]]));
                    group[3u-degree] = sum;
                }
            } else {
                for (unsigned b = 0; b < SYDO_RSD_BALL_TERMS; ++b) {
                    unsigned mask = masks[b], degree = degrees[mask];
                    group[degree] = field_product_add(group[degree],
                        field_product_mul(coefficients[a][b],monomials[mask]));
                }
            }
            /* Combine the two selector variables after summing their coefficients. */
            unsigned variable = a == 1 ? 1 : 0;
            for (unsigned p = 0; p < 4; ++p) {
                if (prover) {
                    value = p == 3 ? leading : field_product_reduce(group[p]);
                    if (!a) {
                        if (p < 3) syndrome->c[p + 1] = field_add(syndrome->c[p + 1], value);
                    } else {
                        syndrome->c[p] = field_add(syndrome->c[p], field_mul(value, variables[variable]));
                        if (p < 3) syndrome->c[p + 1] = field_add(syndrome->c[p + 1], field_mask(value, bits[variable]));
                    }
                } else {
                    value = field_add(value, field_mul(field_product_reduce(group[p]), powers[3 - p]));
                }
            }
            if (!prover) syndrome->c[0] = field_add(syndrome->c[0],
                field_mul(value, a ? variables[variable] : powers[1]));
            sydo_wipe(group, sizeof(group));
            sydo_wipe(&leading, sizeof(leading)); sydo_wipe(&value, sizeof(value));
        }
        sydo_wipe(variables, sizeof(variables));
        sydo_wipe(bits, sizeof(bits));
        sydo_wipe(products,sizeof(products));
    }
    if (!prover) {
        sydo_field result = syndrome->c[0];
        for (unsigned c = 0; c < SYDO_SYNDROME_FIELDS; ++c)
            result = field_add(result, field_mul(field_mul(syndrome_element(pk, c), alpha[c]), powers[4]));
        syndrome->c[0] = result;
    }
    sydo_wipe(workspace, sizeof(*workspace));
    free(workspace);
    SYDO_PROFILE_END(prover ? PROFILE_PROVE : PROFILE_CONSTRAINT_VERIFY);
    return 0;
}

static sydo_field hash_finish(const constraint_hash *hash, unsigned coefficient,
                                sydo_field mask, sydo_field syndrome) {
    return field_add(field_add(mask, syndrome),
                      field_add(field_mul(hash->xi0, hash->h0[coefficient]), field_mul(hash->xi1, hash->h1[coefficient])));
}

int rsd_prove(uint8_t proof[SYDO_PROOF_BYTES], uint8_t check[SYDO_SEED_BYTES], const uint8_t pk[SYDO_PK_BYTES],
                const uint8_t witness[SYDO_WITNESS_BYTES], const uint8_t u[SYDO_VOLE_BYTES],
                const uint8_t *columns, const uint8_t challenge[SYDO_CHALLENGE2_BYTES]) {
    constraint_hash hash;
    polynomial z;
    sydo_field powers[5] = {{{1}}}, masks[4];
    hash_init(&hash, challenge);
    int status = constraints(&z, &hash, pk, witness, columns, challenge, powers, 1);
    if (status) return status;
    masks[0] = tail_value(columns, 0);
    masks[1] = field_add(field_read(u + SYDO_WITNESS_BYTES), tail_value(columns, 1));
    masks[2] = field_add(field_read(u + SYDO_WITNESS_BYTES + SYDO_SEED_BYTES), tail_value(columns, 2));
    masks[3] = field_read(u + SYDO_WITNESS_BYTES + 2 * SYDO_SEED_BYTES);
    field_write(check, hash_finish(&hash, 0, masks[0], z.c[0]));
    for (unsigned p = 1; p < 4; ++p) field_write(proof + SYDO_SEED_BYTES * (p - 1), hash_finish(&hash, p, masks[p], z.c[p]));
    sydo_wipe(&hash, sizeof(hash)); sydo_wipe(&z, sizeof(z)); sydo_wipe(masks, sizeof(masks));
    return 0;
}

int rsd_verify(uint8_t check[SYDO_SEED_BYTES], const uint8_t pk[SYDO_PK_BYTES], const uint8_t correction[SYDO_WITNESS_BYTES],
                 const uint8_t *columns, const uint8_t challenge[SYDO_CHALLENGE2_BYTES],
                 const uint8_t delta[SYDO_SEED_BYTES], const uint8_t proof[SYDO_PROOF_BYTES]) {
    constraint_hash hash;
    polynomial z;
    sydo_field powers[5];
    powers[0] = field_one();
    powers[1] = field_read(delta);
    for (unsigned i = 2; i <= 4; ++i) powers[i] = field_mul(powers[i - 1], powers[1]);
    hash_init(&hash, challenge);
    int status = constraints(&z, &hash, pk, correction, columns, challenge, powers, 0);
    if (status) return status;
    sydo_field mask = field_zero();
    for (unsigned i = 0; i < 3; ++i) mask = field_add(mask, field_mul(tail_value(columns, i), powers[i]));
    for (unsigned i = 1; i < 4; ++i) mask = field_add(mask, field_mul(field_read(proof + SYDO_SEED_BYTES * (i - 1)), powers[i]));
    field_write(check, hash_finish(&hash, 0, mask, z.c[0]));
    sydo_wipe(&hash, sizeof(hash)); sydo_wipe(&z, sizeof(z));
    return 0;
}
