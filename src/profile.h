#ifndef SYDO_PROFILE_H
#define SYDO_PROFILE_H

#include <stdio.h>

enum sydo_profile_stage {
    PROFILE_SIGN, PROFILE_VERIFY, PROFILE_TREE, PROFILE_LEAF,
    PROFILE_COMMITMENT_HASH, PROFILE_VOLE, PROFILE_VOLE_CHECK,
    PROFILE_MATRIX_EXPAND, PROFILE_MATRIX_FOLD, PROFILE_PROVE,
    PROFILE_CONSTRAINT_VERIFY, PROFILE_GRIND, PROFILE_OPEN,
    PROFILE_RECONSTRUCT, PROFILE_XOF, PROFILE_STAGE_COUNT
};

#ifdef SYDO_PROFILE
void profile_begin(enum sydo_profile_stage stage);
void profile_end(enum sydo_profile_stage stage);
void profile_reset(void);
int profile_write(FILE *output);
#define SYDO_PROFILE_BEGIN(stage) profile_begin(stage)
#define SYDO_PROFILE_END(stage) profile_end(stage)
#else
#define SYDO_PROFILE_BEGIN(stage) ((void)0)
#define SYDO_PROFILE_END(stage) ((void)0)
#endif

#endif
