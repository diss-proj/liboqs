/**
 * @file api.h
 * @brief NIST KEM API used by the HQC-KEM IND-CCA2 scheme
 */

#ifndef HQCv5_192_API_H
#define HQCv5_192_API_H

#define CRYPTO_ALGNAME "HQC-3"

#define hqcv5_192_CRYPTO_SECRETKEYBYTES  4602
#define hqcv5_192_CRYPTO_PUBLICKEYBYTES  4514
#define hqcv5_192_CRYPTO_BYTES           32
#define hqcv5_192_CRYPTO_CIPHERTEXTBYTES 8978

// As a technicality, the public key is appended to the secret key in order to respect the NIST API.
// Without this constraint, hqcv5_192_CRYPTO_SECRETKEYBYTES would be defined as 32

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif  // HQC_API_H
