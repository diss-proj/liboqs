/**
 * @file kem.c
 * @brief Implementation of api.h
 */

#include <stdint.h>
#include <string.h>
#include "api.h"
#include "crypto_memset.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "symmetric.h"
#include "vector.h"

// #ifdef VERBOSE
#include <stdio.h>
// #endif

/**
 * @brief Generates a keypair for the KEM (Key Encapsulation Mechanism) scheme.
 *
 * This function generates a public/private keypair used for key encapsulation and decapsulation.
 * The encapsulation key (`ek`) is used to encapsulate a shared secret, while the decapsulation key (`dk`)
 * is used to recover it.
 *
 * @param[out] ek_kem Pointer to the output buffer where the encapsulation key will be stored.
 * @param[out] dk_kem Pointer to the output buffer where the decapsulation key will be stored.
 *
 * @return 0 on success.
 *
 * @pre The PRNG **must be seeded** with ::prng_init() before calling this function.
 * @warning This function calls ::prng_get_bytes() to sample `seed_kem`. If the PRNG has not been
 *          properly seeded beforehand, the generated keys will be insecure/predictable.
 * @note An example of correct seeding is provided in `main_hqc.c` (see `hqcv5_128_init_randomness()`), which
 *       seeds the PRNG using `syscall(SYS_getrandom, ...)` (32 bytes) by default..
 * @see prng_init, prng_get_bytes, main_hqc.c
 */
int hqcv5_128_crypto_kem_keypair(uint8_t *ek_kem, uint8_t *dk_kem) {
#ifdef VERBOSE
    printf("\n\n\n### KEYGEN ###");
#endif
    printf("hqcv5_128_PUBLIC_KEY_BYTES: %d", hqcv5_128_PUBLIC_KEY_BYTES);
    uint8_t seed_kem[hqcv5_128_SEED_BYTES] = {0};
    uint8_t sigma[hqcv5_128_PARAM_SECURITY_BYTES] = {0};
    uint8_t seed_pke[hqcv5_128_SEED_BYTES] = {0};
    shake256_xof_ctx ctx_kem;

    uint8_t ek_pke[hqcv5_128_PUBLIC_KEY_BYTES] = {0};
    uint8_t dk_pke[hqcv5_128_SEED_BYTES] = {0};

    // Sample seed_kem
    prng_get_bytes(seed_kem, hqcv5_128_SEED_BYTES);

    // Compute seed_pke and randomness sigma
    xof_init(&ctx_kem, seed_kem, hqcv5_128_SEED_BYTES);
    xof_get_bytes(&ctx_kem, seed_pke, hqcv5_128_SEED_BYTES);
    xof_get_bytes(&ctx_kem, sigma, hqcv5_128_PARAM_SECURITY_BYTES);

    // Compute HQC-PKE keypair
    hqcv5_128_hqc_pke_keygen(ek_pke, dk_pke, seed_pke);

    // Compute HQC-KEM keypair
    memcpy(ek_kem, ek_pke, hqcv5_128_PUBLIC_KEY_BYTES);
    memcpy(dk_kem, ek_kem, hqcv5_128_PUBLIC_KEY_BYTES);
    memcpy(dk_kem + hqcv5_128_PUBLIC_KEY_BYTES, dk_pke, hqcv5_128_SEED_BYTES);
    memcpy(dk_kem + hqcv5_128_PUBLIC_KEY_BYTES + hqcv5_128_SEED_BYTES, sigma, hqcv5_128_PARAM_SECURITY_BYTES);
    memcpy(dk_kem + hqcv5_128_PUBLIC_KEY_BYTES + hqcv5_128_SEED_BYTES + hqcv5_128_PARAM_SECURITY_BYTES, seed_kem, hqcv5_128_SEED_BYTES);

#ifdef VERBOSE
    printf("\n\nseed_kem: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", seed_kem[i]);
    printf("\n\nseed_pke: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", seed_pke[i]);
    printf("\n\nsigma: ");
    for (int i = 0; i < hqcv5_128_PARAM_SECURITY_BYTES; ++i) printf("%02x", sigma[i]);
#endif

    // Zeroize sensitive data
    hqcv5_128_memset_zero(seed_kem, sizeof seed_kem);
    hqcv5_128_memset_zero(sigma, sizeof sigma);
    hqcv5_128_memset_zero(seed_pke, sizeof seed_pke);
    hqcv5_128_memset_zero(dk_pke, sizeof dk_pke);

    return 0;
}

/**
 * @brief Performs key encapsulation using the KEM scheme.
 *
 * This function uses the encapsulation key (`ek`) to generate a ciphertext (`c_kem`) and a shared secret (`K`)..
 *
 * @param[out] c_kem   Pointer to the output buffer where the KEM ciphertext will be stored.
 * @param[out] K       Pointer to the output buffer where the shared secret will be stored.
 * @param[in]  ek_kem      Pointer to the encapsulation key.
 *
 * @return Returns 0 on success.
 *
 * @pre The PRNG **must be seeded** with ::prng_init() before calling this function.
 * @warning This function calls ::prng_get_bytes() to sample `seed_kem`. If the PRNG has not been
 *          properly seeded beforehand, the generated keys will be insecure/predictable.
 * @note An example of correct seeding is provided in `main_hqc.c` (see `hqcv5_128_init_randomness()`), which
 *       seeds the PRNG using `syscall(SYS_getrandom, ...)` (32 bytes) by default..
 * @see prng_init, prng_get_bytes, main_hqc.c
 */
int hqcv5_128_crypto_kem_enc(uint8_t *c_kem, uint8_t *K, const uint8_t *ek_kem) {
#ifdef VERBOSE
    printf("\n\n\n\n### ENCAPS ###");
#endif

    uint8_t m[hqcv5_128_PARAM_SECURITY_BYTES] = {0};
    uint8_t K_theta[hqcv5_128_SHARED_SECRET_BYTES + hqcv5_128_SEED_BYTES] = {0};
    uint8_t theta[hqcv5_128_SEED_BYTES] = {0};
    uint8_t hash_ek_kem[hqcv5_128_SEED_BYTES] = {0};
    hqcv5_128_ciphertext_kem_t c_kem_t = {0};

    // Sample message m and salt
    prng_get_bytes(m, hqcv5_128_PARAM_SECURITY_BYTES);
    prng_get_bytes(c_kem_t.salt, hqcv5_128_SALT_BYTES);

    // Compute shared key K and ciphertext c_kem
    hash_h(hash_ek_kem, ek_kem);
    hash_g(K_theta, hash_ek_kem, m, c_kem_t.salt);
    memcpy(theta, K_theta + hqcv5_128_SEED_BYTES, hqcv5_128_SEED_BYTES);
    hqcv5_128_hqc_pke_encrypt(&c_kem_t.c_pke, ek_kem, (uint64_t *)m, theta);

    hqcv5_128_hqc_c_kem_to_string(c_kem, &c_kem_t);
    memcpy(K, K_theta, hqcv5_128_SHARED_SECRET_BYTES);

#ifdef VERBOSE
    printf("\n\nek_kem: ");
    for (int i = 0; i < hqcv5_128_PUBLIC_KEY_BYTES; ++i) printf("%02x", ek_kem[i]);
    printf("\n\nm: ");
    hqcv5_128_vect_print((uint64_t *)m, hqcv5_128_PARAM_SECURITY_BYTES);
    printf("\n\nsalt: ");
    for (int i = 0; i < hqcv5_128_SALT_BYTES; ++i) printf("%02x", c_kem_t.salt[i]);
    printf("\n\nH(ek_kem): ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", hash_ek_kem[i]);
    printf("\n\ntheta: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", theta[i]);
    printf("\n\nc_kem: ");
    for (int i = 0; i < hqcv5_128_CIPHERTEXT_BYTES; ++i) printf("%02x", c_kem[i]);
    printf("\n\nK: ");
    for (int i = 0; i < hqcv5_128_SHARED_SECRET_BYTES; ++i) printf("%02x", K[i]);
#endif

    // Zeroize sensitive data
    hqcv5_128_memset_zero(m, sizeof m);
    hqcv5_128_memset_zero(K_theta, sizeof K_theta);
    hqcv5_128_memset_zero(theta, sizeof theta);

    return 0;
}

/**
 * @brief Performs key decapsulation using the KEM scheme.
 *
 * This function uses the decapsulation key (`dk`) to recover the shared secret (`K_prime`)
 * from the given KEM ciphertext (`c_kem`), which was generated during encapsulation.
 *
 * @param[out] K_prime   Pointer to the output buffer where the recovered shared secret will be stored.
 * @param[in]  c_kem     Pointer to the input KEM ciphertext.
 * @param[in]  dk_kem    Pointer to the decapsulation key.
 *
 * @return Returns 0 on success.
 */
int hqcv5_128_crypto_kem_dec(uint8_t *K_prime, const uint8_t *c_kem, const uint8_t *dk_kem) {
#ifdef VERBOSE
    printf("\n\n\n\n### DECAPS ###");
#endif

    uint8_t ek_pke[hqcv5_128_PUBLIC_KEY_BYTES] = {0};
    uint8_t dk_pke[hqcv5_128_SEED_BYTES] = {0};
    uint8_t sigma[hqcv5_128_PARAM_SECURITY_BYTES] = {0};
    uint8_t m_prime[hqcv5_128_PARAM_SECURITY_BYTES] = {0};
    uint8_t hash_ek_kem[hqcv5_128_SEED_BYTES] = {0};
    uint8_t K_theta_prime[hqcv5_128_SHARED_SECRET_BYTES + hqcv5_128_SEED_BYTES] = {0};
    uint8_t K_bar[hqcv5_128_SHARED_SECRET_BYTES] = {0};
    uint8_t theta_prime[hqcv5_128_SEED_BYTES] = {0};
    hqcv5_128_ciphertext_kem_t c_kem_t = {0};
    hqcv5_128_ciphertext_kem_t c_kem_prime_t = {0};
    uint8_t result;

    // Parse decapsulation key dk_kem
    memcpy(ek_pke, dk_kem, hqcv5_128_PUBLIC_KEY_BYTES);
    memcpy(dk_pke, dk_kem + hqcv5_128_PUBLIC_KEY_BYTES, hqcv5_128_SEED_BYTES);
    memcpy(sigma, dk_kem + hqcv5_128_PUBLIC_KEY_BYTES + hqcv5_128_SEED_BYTES, hqcv5_128_PARAM_SECURITY_BYTES);

    // Parse ciphertext c_kem
    hqcv5_128_hqc_c_kem_from_string(&c_kem_t.c_pke, c_kem_t.salt, c_kem);

    // Compute message m_prime
    result = hqcv5_128_hqc_pke_decrypt((uint64_t *)m_prime, dk_pke, &c_kem_t.c_pke);

    // Compute shared key K_prime and ciphertext c_kem_prime
    hash_h(hash_ek_kem, ek_pke);
    hash_g(K_theta_prime, hash_ek_kem, m_prime, c_kem_t.salt);
    memcpy(K_prime, K_theta_prime, hqcv5_128_SHARED_SECRET_BYTES);
    memcpy(theta_prime, K_theta_prime + hqcv5_128_SHARED_SECRET_BYTES, hqcv5_128_SEED_BYTES);

    hqcv5_128_hqc_pke_encrypt(&c_kem_prime_t.c_pke, ek_pke, (uint64_t *)m_prime, theta_prime);
    memcpy(c_kem_prime_t.salt, c_kem_t.salt, hqcv5_128_SALT_BYTES);

    // Compute rejection key K_bar
    hash_j(K_bar, hash_ek_kem, sigma, &c_kem_t);
    result |= hqcv5_128_vect_compare((uint8_t *)c_kem_t.c_pke.u, (uint8_t *)c_kem_prime_t.c_pke.u, hqcv5_128_VEC_N_SIZE_BYTES);
    result |= hqcv5_128_vect_compare((uint8_t *)c_kem_t.c_pke.v, (uint8_t *)c_kem_prime_t.c_pke.v, hqcv5_128_VEC_N1N2_SIZE_BYTES);
    result |= hqcv5_128_vect_compare(c_kem_t.salt, c_kem_prime_t.salt, hqcv5_128_SALT_BYTES);
    result -= 1;
    for (size_t i = 0; i < hqcv5_128_SHARED_SECRET_BYTES; ++i) {
        K_prime[i] = (K_prime[i] & result) ^ (K_bar[i] & ~result);
    }

#ifdef VERBOSE
    printf("\n\nek_pke: ");
    for (int i = 0; i < hqcv5_128_PUBLIC_KEY_BYTES; ++i) printf("%02x", ek_pke[i]);
    printf("\n\ndk_pke: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", dk_pke[i]);
    printf("\n\nc_kem: ");
    for (int i = 0; i < hqcv5_128_CIPHERTEXT_BYTES; ++i) printf("%02x", c_kem[i]);
    printf("\n\nm_prime: ");
    hqcv5_128_vect_print((uint64_t *)m_prime, hqcv5_128_PARAM_SECURITY_BYTES);
    printf("\n\nH(ek_kem): ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", hash_ek_kem[i]);
    printf("\n\ntheta_prime: ");
    for (int i = 0; i < hqcv5_128_SEED_BYTES; ++i) printf("%02x", theta_prime[i]);
    printf("\n\n\n# Checking Ciphertext - Begin #");
    printf("\n\nc_kem_prime_t.c_pke.u: ");
    hqcv5_128_vect_print(c_kem_prime_t.c_pke.u, hqcv5_128_VEC_N_SIZE_BYTES);
    printf("\n\nc_kem_prime_t.c_pke.v: ");
    hqcv5_128_vect_print(c_kem_prime_t.c_pke.v, hqcv5_128_VEC_N1N2_SIZE_BYTES);
    printf("\n\nsalt: ");
    for (int i = 0; i < hqcv5_128_SALT_BYTES; ++i) printf("%02x", c_kem_prime_t.salt[i]);
    printf("\n\n# Checking Ciphertext - End #\n");
    printf("\n\nK_prime: ");
    for (int i = 0; i < hqcv5_128_SHARED_SECRET_BYTES; ++i) printf("%02x", K_prime[i]);
#endif

    // Zeroize sensitive data
    hqcv5_128_memset_zero(dk_pke, sizeof dk_pke);
    hqcv5_128_memset_zero(sigma, sizeof sigma);
    hqcv5_128_memset_zero(m_prime, sizeof m_prime);
    hqcv5_128_memset_zero(K_theta_prime, sizeof K_theta_prime);
    hqcv5_128_memset_zero(K_bar, sizeof K_bar);
    hqcv5_128_memset_zero(theta_prime, sizeof theta_prime);

    return 0;
}
