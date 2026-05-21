/**
* @file parameters.h
* @brief Parameters of the HQC-KEM IND-CCA2 scheme
 */

#ifndef hqcv5_128_HQC_PARAMETERS_H
#define hqcv5_128_HQC_PARAMETERS_H

#include "api.h"

#define CEIL_DIVIDE(a, b) (((a) / (b)) + ((a) % (b) == 0 ? 0 : 1)) /*!< Divide a by b and ceil the result*/
#define BITMASK(a, size)  ((1UL << (a % size)) - 1)                /*!< Create a mask*/

#define hqcv5_128_PARAM_N                     17669       ///< Define the parameter n of the scheme
#define hqcv5_128_PARAM_N1                    46          ///< Define the parameter n1 of the scheme (length of Reed–Solomon code)
#define hqcv5_128_PARAM_N2                    384         ///< Define the parameter n2 of the scheme (length of Duplicated Reed–Muller code)
#define hqcv5_128_PARAM_N1N2                  17664       ///< Define the length in bits of the concatenated code
#define hqcv5_128_PARAM_OMEGA                 66          ///< Define the parameter omega of the scheme
#define hqcv5_128_PARAM_OMEGA_E               75          ///< Define the parameter omega_e of the scheme
#define hqcv5_128_PARAM_OMEGA_R               75          ///< Define the parameter omega_r of the scheme
#define hqcv5_128_PARAM_SECURITY              128         ///< Define the security level corresponding to the chosen parameters
#define hqcv5_128_PARAM_SECURITY_BYTES        16          ///< Define the security level in bytes
#define hqcv5_128_PARAM_DFR_EXP               128         ///< Define the decryption failure rate exponent

#define hqcv5_128_SECRET_KEY_BYTES            hqcv5_128_CRYPTO_SECRETKEYBYTES   ///< Define the size of the secret key in bytes
#define hqcv5_128_PUBLIC_KEY_BYTES            hqcv5_128_CRYPTO_PUBLICKEYBYTES   ///< Define the size of the public key in bytes
#define hqcv5_128_SHARED_SECRET_BYTES         hqcv5_128_CRYPTO_BYTES            ///< Define the size of the shared secret in bytes
#define hqcv5_128_CIPHERTEXT_BYTES            hqcv5_128_CRYPTO_CIPHERTEXTBYTES  ///< Define the size of the ciphertext in bytes

#define hqcv5_128_VEC_N_SIZE_BYTES            CEIL_DIVIDE(hqcv5_128_PARAM_N, 8)     ///< Size of array to store hqcv5_128_PARAM_N bits in bytes
#define hqcv5_128_VEC_K_SIZE_BYTES            hqcv5_128_PARAM_K                     ///< Size of array to store hqcv5_128_PARAM_K bits in bytes
#define hqcv5_128_VEC_N1_SIZE_BYTES           hqcv5_128_PARAM_N1                    ///< Size of array to store hqcv5_128_PARAM_N1 bits in bytes
#define hqcv5_128_VEC_N1N2_SIZE_BYTES         CEIL_DIVIDE(hqcv5_128_PARAM_N1N2, 8)  ///< Size of array to store hqcv5_128_PARAM_N1N2 bits in bytes

#define hqcv5_128_VEC_N_SIZE_64               CEIL_DIVIDE(hqcv5_128_PARAM_N, 64)    ///< Size of array to store hqcv5_128_PARAM_N bits in 64-bit words
#define hqcv5_128_VEC_N1_SIZE_64              CEIL_DIVIDE(hqcv5_128_PARAM_N1, 8)    ///< Size of array to store hqcv5_128_PARAM_N1 bits in 64-bit words
#define hqcv5_128_VEC_N1N2_SIZE_64            CEIL_DIVIDE(hqcv5_128_PARAM_N1N2, 64) ///< Size of array to store hqcv5_128_PARAM_N1N2 bits in 64-bit words

#define hqcv5_128_PARAM_DELTA                 15          ///< Define the error-correcting capacity (delta) of the Reed–Solomon code
#define hqcv5_128_PARAM_M                     8           ///< Define the degree m of the Galois field GF(2^m)
#define hqcv5_128_PARAM_GF_POLY               0x11D       ///< Generator polynomial of GF(2^hqcv5_128_PARAM_M) in hexadecimal form
#define hqcv5_128_PARAM_GF_MUL_ORDER          255         ///< Size of the multiplicative group of GF(2^hqcv5_128_PARAM_M) (2^hqcv5_128_PARAM_M−1)
#define hqcv5_128_PARAM_K                     16          ///< Define the size of the information bits of the Reed–Solomon code
#define hqcv5_128_PARAM_G                     31          ///< Define the size of the generator polynomial of the Reed–Solomon code
#define hqcv5_128_PARAM_FFT                   4           ///< Exponent for additive FFT (2^hqcv5_128_PARAM_FFT points)

#define hqcv5_128_RS_POLY_COEFS                                                                                                \
    89,  69, 153, 116, 176, 117, 111, 75,  73, 233, 242, 233, 65,  210, 21,  139, 103, 173, 67,  118,                   \
    105, 210, 174, 110, 74,  69, 228, 82,  255, 181, 1                                                     ///< Coefficients of the Reed–Solomon generator polynomial

#define hqcv5_128_SEED_BYTES                  32          ///< Define the size of the seed in bytes
#define hqcv5_128_SALT_BYTES                  16          ///< Define the size of a salt in bytes

#define hqcv5_128_PARAM_N_MU 243079ULL   ///<  Define a precomputed multiplier for Barrett reduction mu = floor(2^32 / hqcv5_128_PARAM_N)
#define hqcv5_128_UTILS_REJECTION_THRESHOLD             16767881  ///< Rejection threshold for uniform sampling in [0, hqcv5_128_PARAM_N)

#endif // hqcv5_128_HQC_PARAMETERS_H
