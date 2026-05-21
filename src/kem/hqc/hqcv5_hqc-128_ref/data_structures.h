/**
 * @file    data_structures.h
 * @brief   HQC-PKE and HQC-KEM ciphertext data structures.
 */

#ifndef hqcv5_128_HQC_DATA_STRUCTURES_H
#define hqcv5_128_HQC_DATA_STRUCTURES_H

#include <stdint.h>
#include "parameters.h"

/**
 * @brief Public-key encryption ciphertext.
 *
 * - u: length hqcv5_128_VEC_N_SIZE_64 words
 * - v: length hqcv5_128_VEC_N_SIZE_64 words
 */
typedef struct {
    uint64_t u[hqcv5_128_VEC_N_SIZE_64]; /**< first vector half */
    uint64_t v[hqcv5_128_VEC_N_SIZE_64]; /**< second vector half */
} hqcv5_128_ciphertext_pke_t;

/**
 * @brief Key-encapsulation mechanism ciphertext.
 *
 * Wraps a PKE ciphertext along with the salt used in the KEM:
 * - c_pke: the ciphertext for PKE
 * - salt:  additional randomness (hqcv5_128_SALT_BYTES bytes)
 */
typedef struct {
    hqcv5_128_ciphertext_pke_t c_pke;   /**< embedded PKE ciphertext */
    uint8_t salt[hqcv5_128_SALT_BYTES]; /**< per-encapsulation salt */
} hqcv5_128_ciphertext_kem_t;

/**
 * @brief 128-bit codeword representation.
 *
 * A Reed-Muller RM(1,7) codeword is 128 bits long. This union allows
 * viewing the same data as an array of bytes or 32-bit words.
 */
typedef union {
    uint8_t u8[16];  /**< Byte-wise access (16 bytes) */
    uint32_t u32[4]; /**< Word-wise access (4 32-bit words) */
} hqcv5_128_rm_codeword_t;

#endif  // hqcv5_128_HQC_DATA_STRUCTURES_H
