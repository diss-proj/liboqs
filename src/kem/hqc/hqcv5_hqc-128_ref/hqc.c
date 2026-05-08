/**
 * @file hqc.c
 * @brief High-level HQC-PKE API implementation
 */

#include "hqc.h"
#include <stdint.h>
#include <string.h>
#include "code.h"
#include "crypto_memset.h"
#include "gf2x.h"
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"
#ifdef VERBOSE
#include <stdio.h>
#endif

/**
 * @brief Generates a key pair for the HQC public-key encryption (PKE) scheme.
 *
 * This function creates a public encryption key (`ek_pke`) and a private decryption key (`dk_pke`)
 * for use in the HQC PKE scheme. The key generation process is seeded with the given `seed` input.
 *
 * @param[out] ek_pke  Pointer to the buffer that will receive the encryption key.
 * @param[out] dk_pke  Pointer to the buffer that will receive the decryption key.
 * @param[in]  seed    Pointer to the seed used to deterministically generate the key pair.
 *
 */
void hqcv5_128_hqc_pke_keygen(uint8_t *ek_pke, uint8_t *dk_pke, uint8_t *seed) {
    uint8_t keypair_seed[2 * hqcv5_128_SEED_BYTES] = {0};
    uint8_t *seed_dk = keypair_seed;
    uint8_t *seed_ek = keypair_seed + hqcv5_128_SEED_BYTES;
    hqcv5_128_shake256_xof_ctx dk_xof_ctx = {0};
    hqcv5_128_shake256_xof_ctx ek_xof_ctx = {0};

    uint64_t x[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t y[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t h[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t s[hqcv5_128_VEC_N_SIZE_64] = {0};

    // Derive keypair seeds
    hqcv5_128_hash_i(keypair_seed, seed);

    // Compute decryption key
    hqcv5_128_xof_init(&dk_xof_ctx, seed_dk, hqcv5_128_SEED_BYTES);
    hqcv5_128_vect_sample_fixed_weight1(&dk_xof_ctx, y, hqcv5_128_PARAM_OMEGA);
    hqcv5_128_vect_sample_fixed_weight1(&dk_xof_ctx, x, hqcv5_128_PARAM_OMEGA);

    // Compute encryption key
    hqcv5_128_xof_init(&ek_xof_ctx, seed_ek, hqcv5_128_SEED_BYTES);
    hqcv5_128_vect_set_random(&ek_xof_ctx, h);
    hqcv5_128_vect_mul(s, y, h);
    hqcv5_128_vect_add(s, x, s, hqcv5_128_VEC_N_SIZE_64);

    // Parse encryption key to string
    memcpy(ek_pke, seed_ek, hqcv5_128_SEED_BYTES);
    memcpy(ek_pke + hqcv5_128_SEED_BYTES, s, hqcv5_128_VEC_N_SIZE_BYTES);

    // Parse decryption key to string
    memcpy(dk_pke, seed_dk, hqcv5_128_SEED_BYTES);

#ifdef VERBOSE
    printf("\n\nseed_dk: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", seed_dk[i]);
    printf("\n\nseed_ek: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", seed_ek[i]);
    printf("\n\ny: ");
    hqcv5_128_vect_print(y, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nx: ");
    hqcv5_128_vect_print(x, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nh: ");
    hqcv5_128_vect_print(h, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\ns: ");
    hqcv5_128_vect_print(s, hqcv5_128_VEC_N_SIZE_BYTES);
#endif

    // Zeroize sensitive data
    hqcv5_128_memset_zero(keypair_seed, sizeof keypair_seed);
    hqcv5_128_memset_zero(x, sizeof x);
    hqcv5_128_memset_zero(y, sizeof y);
    hqcv5_128_memset_zero(&dk_xof_ctx, sizeof dk_xof_ctx);
}

/**
 * @brief Encrypts a message using the HQC public-key encryption (PKE) scheme.
 *
 * This function performs encryption in the HQC PKE scheme. It uses the given encryption key (`ek_pke`)
 * and encryption randomness (`theta`) to encrypt the message `m`, producing a ciphertext `c_pke`.
 *
 * @param[out] c_pke     Pointer to the output ciphertext structure (PKE ciphertext).
 * @param[in]  ek_pke    Pointer to the encryption key.
 * @param[in]  m         Pointer to the message to be encrypted.
 * @param[in]  theta     Pointer to the encryption randomness used during encryption.
 *
 */
void hqcv5_128_hqc_pke_encrypt(hqcv5_128_ciphertext_pke_t *c_pke, const uint8_t *ek_pke, const uint64_t *m, const uint8_t *theta) {
    hqcv5_128_shake256_xof_ctx theta_xof_ctx = {0};
    uint64_t h[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t s[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t r1[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t r2[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t e[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t tmp[hqcv5_128_VEC_N_SIZE_64] = {0};

    // Initialize Xof using theta
    hqcv5_128_xof_init(&theta_xof_ctx, theta, hqcv5_128_SEED_BYTES);

    // Retrieve h and s from public key
    hqcv5_128_hqc_ek_pke_from_string(h, s, ek_pke);

    // Generate re, e and r1
    hqcv5_128_vect_sample_fixed_weight2(&theta_xof_ctx, r2, hqcv5_128_PARAM_OMEGA_R);
    hqcv5_128_vect_sample_fixed_weight2(&theta_xof_ctx, e, hqcv5_128_PARAM_OMEGA_E);
    hqcv5_128_vect_sample_fixed_weight2(&theta_xof_ctx, r1, hqcv5_128_PARAM_OMEGA_R);

    // Compute u = r1 + r2.h
    hqcv5_128_vect_mul(c_pke->u, r2, h);
    hqcv5_128_vect_add(c_pke->u, r1, c_pke->u, hqcv5_128_VEC_N_SIZE_64);

    // Compute v = C.hqcv5_128_encode(m)
    hqcv5_128_code_encode(c_pke->v, m);

    // Compute v = C.hqcv5_128_encode(m) + Truncate(s.r2 + e)
    hqcv5_128_vect_mul(tmp, r2, s);
    hqcv5_128_vect_add(tmp, e, tmp, hqcv5_128_VEC_N_SIZE_64);
    hqcv5_128_vect_truncate(tmp);
    hqcv5_128_vect_add(c_pke->v, c_pke->v, tmp, hqcv5_128_VEC_N1N2_SIZE_64);

#ifdef VERBOSE
    printf("\n\nh: ");
    hqcv5_128_vect_print(h, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\ns: ");
    hqcv5_128_vect_print(s, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nr1: ");
    hqcv5_128_vect_print(r1, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nr2: ");
    hqcv5_128_vect_print(r2, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\ne: ");
    hqcv5_128_vect_print(e, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nTruncate(s.r2 + e): ");
    hqcv5_128_vect_print(tmp, hqcv5_128_VEC_N1N2_SIZE_BYTES);
    printf("\n\nc_pke->u: ");
    hqcv5_128_vect_print(c_pke->u, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nc_pke->v: ");
    hqcv5_128_vect_print(c_pke->v, hqcv5_128_VEC_N1N2_SIZE_BYTES);
#endif

    // Zeroize sensitive data
    hqcv5_128_memset_zero(r1, sizeof r1);
    hqcv5_128_memset_zero(r2, sizeof r2);
    hqcv5_128_memset_zero(e, sizeof e);
    hqcv5_128_memset_zero(tmp, sizeof tmp);
    hqcv5_128_memset_zero(&theta_xof_ctx, sizeof theta_xof_ctx);
}

/**
 * @brief Decrypts a ciphertext using the HQC public-key encryption (PKE) scheme.
 *
 * This function performs decryption in the HQC PKE scheme. It uses the given decryption key (`dk_pke`)
 * to decrypt the ciphertext `c_pke`, recovering the original message `m`.
 *
 * @param[out] m         Pointer to the output buffer where the decrypted message will be stored.
 * @param[in]  dk_pke    Pointer to the decryption key.
 * @param[in]  c_pke     Pointer to the input ciphertext structure (PKE ciphertext).
 *
 * @return Returns 0 on success.
 *
 */
uint8_t hqcv5_128_hqc_pke_decrypt(uint64_t *m, const uint8_t *dk_pke, const hqcv5_128_ciphertext_pke_t *c_pke) {
    uint64_t y[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t tmp1[hqcv5_128_VEC_N_SIZE_64] = {0};
    uint64_t tmp2[hqcv5_128_VEC_N_SIZE_64] = {0};

    // Parse decryption key dk_pke
    hqcv5_128_hqc_dk_pke_from_string(y, dk_pke);

    // Compute u.y
    hqcv5_128_vect_mul(tmp1, y, c_pke->u);
    // Truncate(u.y)
    hqcv5_128_vect_truncate(tmp1);
    // Compute v - Truncate(u.y)
    hqcv5_128_vect_add(tmp2, c_pke->v, tmp1, hqcv5_128_VEC_N1N2_SIZE_64);

#ifdef VERBOSE
    printf("\n\nc_pke.u: ");
    hqcv5_128_vect_print(c_pke->u, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nc_pke.v: ");
    hqcv5_128_vect_print(c_pke->v, hqcv5_128_VEC_N1N2_SIZE_BYTES);
    printf("\n\ny: ");
    hqcv5_128_vect_print(y, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nTruncate(u.y): ");
    hqcv5_128_vect_print(tmp1, hqcv5_128_VEC_N1N2_SIZE_BYTES);
    printf("\n\nv - Truncate(u.y): ");
    hqcv5_128_vect_print(tmp2, hqcv5_128_VEC_N1N2_SIZE_BYTES);
#endif

    // Compute plaintext m
    hqcv5_128_code_decode(m, tmp2);

    // Zeroize sensitive data
    hqcv5_128_memset_zero(y, sizeof y);
    hqcv5_128_memset_zero(tmp1, sizeof tmp1);
    hqcv5_128_memset_zero(tmp2, sizeof tmp2);

    return 0;
}
