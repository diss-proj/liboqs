/**
 * @file parsing.h
 * @brief Header file for parsing.c
 */

#ifndef hqcv5_256_HQC_PARSING_H
#define hqcv5_256_HQC_PARSING_H


#include <stdint.h>
#include "data_structures.h"
#include "parameters.h"

void hqcv5_256_hqc_dk_pke_from_string(uint64_t *y, const uint8_t *dk_pke);
void hqcv5_256_hqc_ek_pke_from_string(uint64_t *h, uint64_t *s, const uint8_t *ek_pke);

void hqcv5_256_hqc_c_kem_to_string(uint8_t *ct, const hqcv5_256_ciphertext_kem_t *c_kem);
void hqcv5_256_hqc_c_kem_from_string(hqcv5_256_ciphertext_pke_t *c_pke, uint8_t *salt, const uint8_t *ct);

#endif  // hqcv5_256_HQC_PARSING_H
