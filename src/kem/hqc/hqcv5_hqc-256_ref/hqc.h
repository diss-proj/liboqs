/**
 * @file hqc.h
 * @brief Header file for hqc.c
 */

#ifndef hqcv5_256_HQC_HQC_H
#define hqcv5_256_HQC_HQC_H

#include <stdint.h>
#include "parameters.h"
#include "parsing.h"

void hqcv5_256_hqc_pke_keygen(uint8_t *ek_pke, uint8_t *dk_pke, uint8_t *seed);
void hqcv5_256_hqc_pke_encrypt(hqcv5_256_ciphertext_pke_t *c_pke, const uint8_t *ek_pke, const uint64_t *m, const uint8_t *theta);
uint8_t hqcv5_256_hqc_pke_decrypt(uint64_t *m, const uint8_t *dk_pke, const hqcv5_256_ciphertext_pke_t *c_pke);

#endif  // hqcv5_256_HQC_HQC_H
