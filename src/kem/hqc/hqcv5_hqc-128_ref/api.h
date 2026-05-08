/**
 * @file api.h
 * @brief NIST KEM API used by the HQC-KEM IND-CCA2 scheme
 */

#ifndef HQCv5_128_API_H
#define HQCv5_128_API_H

#define CRYPTO_ALGNAME "HQC-1"

#define hqcv5_128_CRYPTO_SECRETKEYBYTES  2321
#define hqcv5_128_CRYPTO_PUBLICKEYBYTES  2241
#define hqcv5_128_CRYPTO_BYTES           32
#define hqcv5_128_CRYPTO_CIPHERTEXTBYTES 4433

// As a technicality, the public key is appended to the secret key in order to respect the NIST API.
// Without this constraint, hqcv5_128_CRYPTO_SECRETKEYBYTES would be defined as 32

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif  // HQC_API_H
