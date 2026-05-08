/**
* @file parameters.h
* @brief Parameters of the HQC-KEM IND-CCA2 scheme
 */

#ifndef hqcv5_192_HQC_PARAMETERS_H
#define hqcv5_192_HQC_PARAMETERS_H

#include "api.h"

#define CEIL_DIVIDE(a, b) (((a) / (b)) + ((a) % (b) == 0 ? 0 : 1)) /*!< Divide a by b and ceil the result*/
#define BITMASK(a, size)  ((1UL << (a % size)) - 1)                /*!< Create a mask*/

#define hqcv5_192_PARAM_N                     35851       ///< Define the parameter n of the scheme
#define hqcv5_192_PARAM_N1                    56          ///< Define the parameter n1 of the scheme (length of Reed-Solomon code)
#define hqcv5_192_PARAM_N2                    640         ///< Define the parameter n2 of the scheme (length of Duplicated Reed-Muller code)
#define hqcv5_192_PARAM_N1N2                  35840       ///< Define the length in bits of the concatenated code
#define hqcv5_192_PARAM_OMEGA                 100         ///< Define the parameter omega of the scheme
#define hqcv5_192_PARAM_OMEGA_E               114         ///< Define the parameter omega_e of the scheme
#define hqcv5_192_PARAM_OMEGA_R               114         ///< Define the parameter omega_r of the scheme
#define hqcv5_192_PARAM_SECURITY              192         ///< Define the security level corresponding to the chosen parameters
#define hqcv5_192_PARAM_SECURITY_BYTES        24          ///< Define the security level in bytes
#define hqcv5_192_PARAM_DFR_EXP               192         ///< Define the decryption failure rate corresponding to the chosen parameters

#define hqcv5_192_SECRET_KEY_BYTES            hqcv5_192_CRYPTO_SECRETKEYBYTES   ///< Define the size of the secret key in bytes
#define hqcv5_192_PUBLIC_KEY_BYTES            hqcv5_192_CRYPTO_PUBLICKEYBYTES   ///< Define the size of the public key in bytes
#define hqcv5_192_SHARED_SECRET_BYTES         hqcv5_192_CRYPTO_BYTES            ///< Define the size of the shared secret in bytes
#define hqcv5_192_CIPHERTEXT_BYTES            hqcv5_192_CRYPTO_CIPHERTEXTBYTES  ///< Define the size of the ciphertext in bytes

#define hqcv5_192_VEC_N_SIZE_BYTES            CEIL_DIVIDE(hqcv5_192_PARAM_N, 8)     ///< Size of array to store hqcv5_192_PARAM_N bits in bytes
#define hqcv5_192_VEC_K_SIZE_BYTES            hqcv5_192_PARAM_K                     ///< Size of array to store hqcv5_192_PARAM_K bits in bytes
#define hqcv5_192_VEC_N1_SIZE_BYTES           hqcv5_192_PARAM_N1                    ///< Size of array to store hqcv5_192_PARAM_N1 bits in bytes
#define hqcv5_192_VEC_N1N2_SIZE_BYTES         CEIL_DIVIDE(hqcv5_192_PARAM_N1N2, 8)  ///< Size of array to store hqcv5_192_PARAM_N1N2 bits in bytes

#define hqcv5_192_VEC_N_SIZE_64               CEIL_DIVIDE(hqcv5_192_PARAM_N, 64)    ///< Size of array to store hqcv5_192_PARAM_N bits in 64-bit words
#define hqcv5_192_VEC_N1_SIZE_64              CEIL_DIVIDE(hqcv5_192_PARAM_N1, 8)    ///< Size of array to store hqcv5_192_PARAM_N1 bits in 64-bit words
#define hqcv5_192_VEC_N1N2_SIZE_64            CEIL_DIVIDE(hqcv5_192_PARAM_N1N2, 64) ///< Size of array to store hqcv5_192_PARAM_N1N2 bits in 64-bit words

#define hqcv5_192_PARAM_DELTA                 16          ///< Define the error-correcting capacity (delta) of the Reed-Solomon code
#define hqcv5_192_PARAM_M                     8           ///< Define the degree m of the Galois field GF(2^m)
#define hqcv5_192_PARAM_GF_POLY               0x11D       ///< Generator polynomial of GF(2^hqcv5_192_PARAM_M) in hexadecimal form
#define hqcv5_192_PARAM_GF_MUL_ORDER          255         ///< Size of the multiplicative group of GF(2^hqcv5_192_PARAM_M) (i.e., 2^hqcv5_192_PARAM_M−1)
#define hqcv5_192_PARAM_K                     24          ///< Define the size of the information bits of the Reed-Solomon code
#define hqcv5_192_PARAM_G                     33          ///< Define the size of the generator polynomial of the Reed-Solomon code
#define hqcv5_192_PARAM_FFT                   5           ///< Exponent for additive FFT (2^hqcv5_192_PARAM_FFT points)

#define hqcv5_192_RS_POLY_COEFS                                                                                                \
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, \
    232, 246, 142, 50, 189, 29, 232, 1                                                                         ///< Coefficients of the Reed-Solomon generator polynomial

#define hqcv5_192_SEED_BYTES                  32          ///< Define the size of the seed in bytes
#define hqcv5_192_SALT_BYTES                  16          ///< Define the size of a salt in bytes

#define hqcv5_192_PARAM_N_MU 119800ULL   ///<  Define a precomputed multiplier for Barrett reduction mu = floor(2^32 / hqcv5_192_PARAM_N)
#define hqcv5_192_UTILS_REJECTION_THRESHOLD             16742417  ///< Rejection threshold for uniform sampling in [0, hqcv5_192_PARAM_N)

#endif // hqcv5_192_HQC_PARAMETERS_H
