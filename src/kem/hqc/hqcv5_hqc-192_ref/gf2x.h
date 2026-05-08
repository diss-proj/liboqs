/**
 * @file gf2x.h
 * @brief Header file for gf2x.c
 */

#ifndef hqcv5_192_HQC_GF2X_H
#define hqcv5_192_HQC_GF2X_H

#include <stdint.h>

void hqcv5_192_vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2);

#endif  // hqcv5_192_HQC_GF2X_H
