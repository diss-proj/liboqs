/**
 * @file vector.h
 * @brief Header file for vector.c
 */

#ifndef hqcv5_192_HQC_VECTOR_H
#define hqcv5_192_HQC_VECTOR_H

#include <immintrin.h>
#include <stdint.h>
#include "symmetric.h"

void hqcv5_192_vect_generate_random_support1(hqcv5_192_shake256_xof_ctx *ctx, uint32_t *support, uint16_t weight);
void hqcv5_192_vect_generate_random_support2(hqcv5_192_shake256_xof_ctx *ctx, uint32_t *support, uint16_t weight);
void hqcv5_192_vect_write_support_to_vector(uint64_t *v, uint32_t *support, uint16_t weight);
void hqcv5_192_vect_sample_fixed_weight1(hqcv5_192_shake256_xof_ctx *ctx, uint64_t *v, uint16_t weight);
void hqcv5_192_vect_sample_fixed_weight2(hqcv5_192_shake256_xof_ctx *ctx, uint64_t *v, uint16_t weight);
void hqcv5_192_vect_set_random(hqcv5_192_shake256_xof_ctx *ctx, uint64_t *v);

void hqcv5_192_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size);
uint8_t hqcv5_192_vect_compare(const uint8_t *v1, const uint8_t *v2, uint32_t size);
void hqcv5_192_vect_truncate(uint64_t *v);

void hqcv5_192_vect_print(const uint64_t *v, const uint32_t size);

#endif  // hqcv5_192_HQC_VECTOR_H
