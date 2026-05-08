/**
 * @file symmetric.h
 * @brief Header file of symmetric.c
 */

#ifndef hqcv5_128_HQC_SYMMETRIC_H
#define hqcv5_128_HQC_SYMMETRIC_H

#include <stdint.h>
#include "data_structures.h"
#include "fips202.h"
#include "parameters.h"

/**
 * @typedef sha3_512_ctx
 * @brief Incremental SHA3-512 hashing context.
 *
 * Alias for the low-level `sha3_512incctx`, used to
 * accumulate input and squeeze out a 512-bit digest.
 */
typedef sha3_512incctx sha3_512_ctx;

/**
 * @typedef sha3_256_ctx
 * @brief Incremental SHA3-256 hashing context.
 *
 * Alias for the low-level `sha3_256incctx`, used to
 * accumulate input and squeeze out a 256-bit digest.
 */
typedef sha3_256incctx sha3_256_ctx;

/**
 * @typedef shake256_xof_ctx
 * @brief Incremental SHAKE-256 extendable-output context.
 *
 * Alias for `shake256incctx`, used to absorb input and
 * generate arbitrary-length XOF output.
 */
typedef shake256incctx shake256_xof_ctx;

/** @def hqcv5_128_HQC_PRNG_DOMAIN
 *  @brief Domain separator for HQC prng function.
 */
#define hqcv5_128_HQC_PRNG_DOMAIN 0

/** @def hqcv5_128_HQC_XOF_DOMAIN
 *  @brief Domain separator for HQC extendable-output function.
 */
#define hqcv5_128_HQC_XOF_DOMAIN 1

/** @def hqcv5_128_HQC_G_FCT_DOMAIN
 *  @brief Domain separator for the G(·) function in HQC.
 */
#define hqcv5_128_HQC_G_FCT_DOMAIN 0

/** @def hqcv5_128_HQC_H_FCT_DOMAIN
 *  @brief Domain separator for the H(·) function in HQC.
 */
#define hqcv5_128_HQC_H_FCT_DOMAIN 1

/** @def hqcv5_128_HQC_I_FCT_DOMAIN
 *  @brief Domain separator for the I(·) function in HQC.
 */
#define hqcv5_128_HQC_I_FCT_DOMAIN 2

/** @def hqcv5_128_HQC_J_FCT_DOMAIN
 *  @brief Domain separator for the J(·) function in HQC.
 */
#define hqcv5_128_HQC_J_FCT_DOMAIN 3

void hqcv5_128_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen);
void hqcv5_128_prng_get_bytes(uint8_t *output, uint32_t outlen);

void hqcv5_128_xof_init(shake256_xof_ctx *xof_ctx, const uint8_t *seed, uint32_t seed_size);
void hqcv5_128_xof_get_bytes(shake256_xof_ctx *xof_ctx, uint8_t *output, uint32_t output_size);

void hqcv5_128_hash_g(uint8_t *output, const uint8_t h_ek[hqcv5_128_SEED_BYTES], const uint8_t m[hqcv5_128_VEC_K_SIZE_BYTES],
            const uint8_t salt[hqcv5_128_SALT_BYTES]);
void hqcv5_128_hash_h(uint8_t *output, const uint8_t pk[hqcv5_128_PUBLIC_KEY_BYTES]);
void hqcv5_128_hash_i(uint8_t *output, const uint8_t *seed);
void hqcv5_128_hash_j(uint8_t *output, const uint8_t h_ek[hqcv5_128_SEED_BYTES], const uint8_t sigma[hqcv5_128_VEC_K_SIZE_BYTES],
            const hqcv5_128_ciphertext_kem_t *c_kem);

#endif  // hqcv5_128_HQC_SYMMETRIC_H
