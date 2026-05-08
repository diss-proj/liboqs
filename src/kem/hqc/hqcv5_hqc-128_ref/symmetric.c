/**
 * @file symmetric.c
 * @brief Cryptographic primitives: a SHAKE-256–based pseudo-random number generator (PRNG) and extendable-output
 * function (XOF), plus hash functions built on SHA3-256 and SHA3-512.
 */

#include "symmetric.h"
#include <stdint.h>

/**
 * @typedef hqcv5_128_shake256_prng_ctx
 * @brief Incremental SHAKE-256 prng context.
 *
 */
shake256incctx hqcv5_128_shake256_prng_ctx;

/**
 * @brief SHAKE-256 with incremental API and domain separation
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[in] entropy_input Pointer to input entropy bytes
 * @param[in] personalization_string Pointer to the personalization string
 * @param[in] enlen Length of entropy string in bytes
 * @param[in] perlen Length of the personalization string in bytes
 */
void hqcv5_128_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen) {
    uint8_t domain = hqcv5_128_HQC_PRNG_DOMAIN;
    shake256_inc_init(&hqcv5_128_shake256_prng_ctx);
    shake256_inc_absorb(&hqcv5_128_shake256_prng_ctx, entropy_input, enlen);
    shake256_inc_absorb(&hqcv5_128_shake256_prng_ctx, personalization_string, perlen);
    shake256_inc_absorb(&hqcv5_128_shake256_prng_ctx, &domain, 1);
    shake256_inc_finalize(&hqcv5_128_shake256_prng_ctx);
}

/**
 * @brief A SHAKE-256 based PRNG
 *
 * Derived from function SHAKE_256 in fips202.c
 *
 * @param[out] output Pointer to output
 * @param[in] outlen length of output in bytes
 */
void hqcv5_128_prng_get_bytes(uint8_t *output, uint32_t outlen) {
    shake256_inc_squeeze(output, outlen, &hqcv5_128_shake256_prng_ctx);
}

/**
 * @brief Initializes a SHAKE256 XOF context with a given seed.
 *
 * @param[out] xof_ctx   Pointer to the XOF context to be initialized.
 * @param[in]  seed      Pointer to the input seed.
 * @param[in]  seed_size Size of the seed in bytes.
 */
void hqcv5_128_xof_init(hqcv5_128_shake256_xof_ctx *xof_ctx, const uint8_t *seed, uint32_t seed_size) {
    uint8_t xof_domain = hqcv5_128_HQC_XOF_DOMAIN;
    shake256_inc_init(xof_ctx);
    shake256_inc_absorb(xof_ctx, seed, seed_size);
    shake256_inc_absorb(xof_ctx, &xof_domain, 1);
    shake256_inc_finalize(xof_ctx);
}

/**
 * @brief Extracts pseudorandom bytes from a SHAKE256 XOF context.
 *
 * @param[in,out] xof_ctx     Pointer to the initialized XOF context.
 * @param[out]    output      Pointer to the buffer where the output bytes will be written.
 * @param[in]     output_size Number of bytes to extract.
 *
 * @details This function squeezes the specified number of pseudorandom bytes from
 * the SHAKE256 XOF context and stores them in the provided output buffer.
 * The context must have been initialized beforehand using `hqcv5_128_xof_init()`.
 */
void hqcv5_128_xof_get_bytes(hqcv5_128_shake256_xof_ctx *xof_ctx, uint8_t *output, uint32_t output_size) {
    const uint8_t bsize = sizeof(uint64_t);
    const uint8_t remainder = output_size % bsize;
    uint8_t tmp[sizeof(uint64_t)];
    shake256_inc_squeeze(output, output_size - remainder, xof_ctx);
    if (remainder != 0) {
        shake256_inc_squeeze(tmp, bsize, xof_ctx);
        output += output_size - remainder;
        for (uint8_t i = 0; i < remainder; i++) {
            output[i] = tmp[i];
        }
    }
}

/**
 * @brief Computes the hash function I (SHA3-512) with domain separation.
 *
 * @param[out] output Pointer to the buffer where the 64-byte hash output will be stored.
 * @param[in]  seed   Pointer to the input seed to be hashed.
 *
 * @details This function implements the random oracle `I` as specified,
 * using the SHA3-512 hash function. It produces a 64-byte output from the given seed.
 */
void hqcv5_128_hash_i(uint8_t *output, const uint8_t *seed) {
    hqcv5_128_sha3_512_ctx i_hash_ctx = {0};
    uint8_t i_domain = hqcv5_128_HQC_I_FCT_DOMAIN;
    sha3_512_inc_init(&i_hash_ctx);
    sha3_512_inc_absorb(&i_hash_ctx, seed, hqcv5_128_SEED_BYTES);
    sha3_512_inc_absorb(&i_hash_ctx, &i_domain, 1);
    sha3_512_inc_finalize(output, &i_hash_ctx);
}

/**
 * @brief Compute the hash function H (SHA3-256) with domain separation.
 *
 * @param[out] output      Buffer (32 bytes) to receive the hash output.
 * @param[in]  ek_kem      Encapsulation key of the KEM.
 */
void hqcv5_128_hash_h(uint8_t *output, const uint8_t ek_kem[hqcv5_128_PUBLIC_KEY_BYTES]) {
    hqcv5_128_sha3_256_ctx h_hash_ctx = {0};
    uint8_t h_domain = hqcv5_128_HQC_H_FCT_DOMAIN;
    sha3_256_inc_init(&h_hash_ctx);
    sha3_256_inc_absorb(&h_hash_ctx, ek_kem, hqcv5_128_PUBLIC_KEY_BYTES);
    sha3_256_inc_absorb(&h_hash_ctx, &h_domain, 1);
    sha3_256_inc_finalize(output, &h_hash_ctx);
}

/**
 * @brief Compute the hash function G (SHA3-512) with domain separation.
 *
 * @param[out] output        Buffer (64 bytes) to receive the hash output.
 * @param[in]  hash_ek_kem   Hash of the KEM encapsulation key.
 * @param[in]  m             Message bytes.
 * @param[in]  salt          Salt value.
 */
void hqcv5_128_hash_g(uint8_t *output, const uint8_t hash_ek_kem[hqcv5_128_SEED_BYTES], const uint8_t m[hqcv5_128_PARAM_SECURITY_BYTES],
            const uint8_t salt[hqcv5_128_SALT_BYTES]) {
    hqcv5_128_sha3_512_ctx g_hash_ctx = {0};
    uint8_t i_domain = hqcv5_128_HQC_G_FCT_DOMAIN;
    sha3_512_inc_init(&g_hash_ctx);
    sha3_512_inc_absorb(&g_hash_ctx, hash_ek_kem, hqcv5_128_SEED_BYTES);
    sha3_512_inc_absorb(&g_hash_ctx, m, hqcv5_128_PARAM_SECURITY_BYTES);
    sha3_512_inc_absorb(&g_hash_ctx, salt, hqcv5_128_SALT_BYTES);
    sha3_512_inc_absorb(&g_hash_ctx, &i_domain, 1);
    sha3_512_inc_finalize(output, &g_hash_ctx);
}

/**
 * @brief Compute the hash function J (SHA3-256) with domain separation.
 *
 * @param[out] output       Buffer (32 bytes) to receive the hash output.
 * @param[in]  hash_ek_kem  Hash of the KEM encapsulation key.
 * @param[in]  sigma        The string sigma.
 * @param[in]  c_kem        Pointer to ciphertext struct (includes c_pke.u, c_pke.v, and salt).
 */
void hqcv5_128_hash_j(uint8_t *output, const uint8_t hash_ek_kem[hqcv5_128_SEED_BYTES], const uint8_t sigma[hqcv5_128_PARAM_SECURITY_BYTES],
            const hqcv5_128_ciphertext_kem_t *c_kem) {
    hqcv5_128_sha3_256_ctx k_hash_ctx = {0};
    uint8_t k_domain = hqcv5_128_HQC_J_FCT_DOMAIN;
    sha3_256_inc_init(&k_hash_ctx);
    sha3_256_inc_absorb(&k_hash_ctx, hash_ek_kem, hqcv5_128_SEED_BYTES);
    sha3_256_inc_absorb(&k_hash_ctx, sigma, hqcv5_128_PARAM_SECURITY_BYTES);
    sha3_256_inc_absorb(&k_hash_ctx, (uint8_t *)c_kem->c_pke.u, hqcv5_128_VEC_N_SIZE_BYTES);
    sha3_256_inc_absorb(&k_hash_ctx, (uint8_t *)c_kem->c_pke.v, hqcv5_128_VEC_N1N2_SIZE_BYTES);
    sha3_256_inc_absorb(&k_hash_ctx, c_kem->salt, hqcv5_128_SALT_BYTES);
    sha3_256_inc_absorb(&k_hash_ctx, &k_domain, 1);
    sha3_256_inc_finalize(output, &k_hash_ctx);
}
