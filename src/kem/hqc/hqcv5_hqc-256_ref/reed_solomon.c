/**
 * @file reed_solomon.c
 * @brief Constant time implementation of Reed-Solomon codes
 */

#include "reed_solomon.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "crypto_memset.h"
#include "fft.h"
#include "gf.h"
#include "parameters.h"
#ifdef VERBOSE
#include <stdbool.h>
#include <stdio.h>
#endif

static uint16_t hqcv5_256_mod(uint16_t i, uint16_t modulus);
static void hqcv5_256_compute_syndromes(uint16_t *syndromes, uint8_t *cdw);
static uint16_t hqcv5_256_compute_elp(uint16_t *sigma, const uint16_t *syndromes);
static void hqcv5_256_compute_roots(uint8_t *error, uint16_t *sigma);
static void hqcv5_256_compute_z_poly(uint16_t *z, const uint16_t *sigma, const uint16_t degree, const uint16_t *syndromes);
static void hqcv5_256_compute_error_values(uint16_t *error_values, const uint16_t *z, const uint8_t *error);
static void hqcv5_256_correct_errors(uint8_t *cdw, const uint16_t *error_values);

/**
 * Returns i modulo the given modulus.
 * i must be less than 2*modulus.
 * Therefore, the return value is either i or i-modulus.
 * @returns i mod (modulus)
 * @param[in] i The integer whose modulo is taken
 * @param[in] modulus The modulus
 */
static uint16_t hqcv5_256_mod(uint16_t i, uint16_t modulus) {
    uint16_t tmp = i - modulus;

    // mask = 0xffff if(i < hqcv5_256_PARAM_GF_MUL_ORDER)
    int16_t mask = -(tmp >> 15);

    return tmp + (mask & modulus);
}

/**
 * @brief Computes the generator polynomial of the primitive Reed-Solomon code with given parameters.
 *
 * Code length is 2^m-1. <br>
 * hqcv5_256_PARAM_DELTA is the targeted correction capacity of the code
 * and receives the real correction capacity (which is at least equal to the target). <br>
 * hqcv5_256_gf_exp and hqcv5_256_gf_log are arrays giving antilog and log of GF(2^m) elements.
 *
 * @param[out] poly Array of size (2*hqcv5_256_PARAM_DELTA + 1) receiving the coefficients of the generator polynomial
 */
void hqcv5_256_compute_generator_poly(uint16_t *poly) {
    poly[0] = 1;
    int tmp_degree = 0;

    for (uint16_t i = 1; i < (2 * hqcv5_256_PARAM_DELTA + 1); ++i) {
        for (size_t j = tmp_degree; j; --j) {
            poly[j] = hqcv5_256_gf_exp[hqcv5_256_mod(hqcv5_256_gf_log[poly[j]] + i, hqcv5_256_PARAM_GF_MUL_ORDER)] ^ poly[j - 1];
        }

        poly[0] = hqcv5_256_gf_exp[hqcv5_256_mod(hqcv5_256_gf_log[poly[0]] + i, hqcv5_256_PARAM_GF_MUL_ORDER)];
        poly[++tmp_degree] = 1;
    }

    printf("\n");
    for (int i = 0; i < (hqcv5_256_PARAM_G); ++i) {
        printf("%d, ", poly[i]);
    }
    printf("\n");
}

/**
 * @brief Encodes a message message of hqcv5_256_PARAM_K bits to a Reed-Solomon codeword codeword of hqcv5_256_PARAM_N1 bytes
 *
 * Following @cite lin1983error (Chapter 4 - Cyclic Codes),
 * We perform a systematic encoding using a linear (hqcv5_256_PARAM_N1 - hqcv5_256_PARAM_K)-stage shift register
 * with feedback connections based on the generator polynomial PARAM_RS_POLY of the Reed-Solomon code.
 *
 * @param[out] cdw Array of size hqcv5_256_VEC_N1_SIZE_64 receiving the encoded message
 * @param[in] msg Array of size VEC_K_SIZE_64 storing the message
 */
void hqcv5_256_reed_solomon_encode(uint64_t *cdw, const uint64_t *msg) {
    size_t i, j, k;
    uint8_t gate_value = 0;

    uint16_t tmp[hqcv5_256_PARAM_G] = {0};
    uint16_t PARAM_RS_POLY[] = {hqcv5_256_RS_POLY_COEFS};

    uint8_t msg_bytes[hqcv5_256_PARAM_K] = {0};
    uint8_t cdw_bytes[hqcv5_256_PARAM_N1] = {0};

    memcpy(msg_bytes, msg, hqcv5_256_PARAM_K);

    for (i = 0; i < hqcv5_256_PARAM_K; ++i) {
        gate_value = msg_bytes[hqcv5_256_PARAM_K - 1 - i] ^ cdw_bytes[hqcv5_256_PARAM_N1 - hqcv5_256_PARAM_K - 1];

        for (j = 0; j < hqcv5_256_PARAM_G; ++j) {
            tmp[j] = hqcv5_256_gf_mul(gate_value, PARAM_RS_POLY[j]);
        }

        for (k = hqcv5_256_PARAM_N1 - hqcv5_256_PARAM_K - 1; k; --k) {
            cdw_bytes[k] = cdw_bytes[k - 1] ^ tmp[k];
        }

        cdw_bytes[0] = tmp[0];
    }

    memcpy(cdw_bytes + hqcv5_256_PARAM_N1 - hqcv5_256_PARAM_K, msg_bytes, hqcv5_256_PARAM_K);
    memcpy(cdw, cdw_bytes, hqcv5_256_PARAM_N1);
}

/**
 * @brief Computes 2 * hqcv5_256_PARAM_DELTA syndromes
 *
 * @param[out] syndromes Array of size 2 * hqcv5_256_PARAM_DELTA receiving the computed syndromes
 * @param[in] cdw Array of size hqcv5_256_PARAM_N1 storing the received vector
 */
void hqcv5_256_compute_syndromes(uint16_t *syndromes, uint8_t *cdw) {
    for (size_t i = 0; i < 2 * hqcv5_256_PARAM_DELTA; ++i) {
        for (size_t j = 1; j < hqcv5_256_PARAM_N1; ++j) {
            syndromes[i] ^= hqcv5_256_gf_mul(cdw[j], hqcv5_256_alpha_ij_pow[i][j - 1]);
        }
        syndromes[i] ^= cdw[0];
    }
}

/**
 * @brief Computes the error locator polynomial (ELP) sigma
 *
 * This is a constant time implementation of Berlekamp's algorithm (see @cite lin1983error (Chapter 6 - BCH
 * Codes). <br> We use the letter p for rho which is initialized at -1. <br> The array X_sigma_p represents the
 * polynomial X^(mu-rho)*sigma_p(X). <br> Instead of maintaining a list of sigmas, we update in place both sigma and
 * X_sigma_p. <br> sigma_copy serves as a temporary save of sigma in case X_sigma_p needs to be updated. <br> We can
 * properly correct only if the degree of sigma does not exceed hqcv5_256_PARAM_DELTA. This means only the first hqcv5_256_PARAM_DELTA + 1
 * coefficients of sigma are of value and we only need to save its first hqcv5_256_PARAM_DELTA - 1 coefficients.
 *
 * @returns the degree of the ELP sigma
 * @param[out] sigma Array of size (at least) hqcv5_256_PARAM_DELTA receiving the ELP
 * @param[in] syndromes Array of size (at least) 2*hqcv5_256_PARAM_DELTA storing the syndromes
 */
static uint16_t hqcv5_256_compute_elp(uint16_t *sigma, const uint16_t *syndromes) {
    uint16_t deg_sigma = 0;
    uint16_t deg_sigma_p = 0;
    uint16_t deg_sigma_copy = 0;
    uint16_t sigma_copy[hqcv5_256_PARAM_DELTA + 1] = {0};
    uint16_t X_sigma_p[hqcv5_256_PARAM_DELTA + 1] = {0, 1};
    uint16_t pp = (uint16_t)-1;  // 2*rho
    uint16_t d_p = 1;
    uint16_t d = syndromes[0];

    uint16_t mask1, mask2, mask12;
    uint16_t deg_X, deg_X_sigma_p;
    uint16_t dd;
    uint16_t mu;

    uint16_t i;

    sigma[0] = 1;
    for (mu = 0; (mu < (2 * hqcv5_256_PARAM_DELTA)); ++mu) {
        // Save sigma in case we need it to update X_sigma_p
        memcpy(sigma_copy, sigma, 2 * (hqcv5_256_PARAM_DELTA));
        deg_sigma_copy = deg_sigma;

        dd = hqcv5_256_gf_mul(d, hqcv5_256_gf_inverse(d_p));

        for (i = 1; (i <= mu + 1) && (i <= hqcv5_256_PARAM_DELTA); ++i) {
            sigma[i] ^= hqcv5_256_gf_mul(dd, X_sigma_p[i]);
        }

        deg_X = mu - pp;
        deg_X_sigma_p = deg_X + deg_sigma_p;

        // mask1 = 0xffff if(d != 0) and 0 otherwise
        mask1 = -((uint16_t)-d >> 15);

        // mask2 = 0xffff if(deg_X_sigma_p > deg_sigma) and 0 otherwise
        mask2 = -((uint16_t)(deg_sigma - deg_X_sigma_p) >> 15);

        // mask12 = 0xffff if the deg_sigma increased and 0 otherwise
        volatile uint16_t mask12__ = mask1 & mask2;
        mask12 = mask12__;
        deg_sigma ^= mask12 & (deg_X_sigma_p ^ deg_sigma);

        if (mu == (2 * hqcv5_256_PARAM_DELTA - 1)) {
            break;
        }

        pp ^= mask12 & (mu ^ pp);
        d_p ^= mask12 & (d ^ d_p);
        for (i = hqcv5_256_PARAM_DELTA; i; --i) {
            X_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (~mask12 & X_sigma_p[i - 1]);
        }

        deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
        d = syndromes[mu + 1];

        for (i = 1; (i <= mu + 1) && (i <= hqcv5_256_PARAM_DELTA); ++i) {
            d ^= hqcv5_256_gf_mul(sigma[i], syndromes[mu + 1 - i]);
        }
    }

    return deg_sigma;
}

/**
 * @brief Computes the error polynomial error from the error locator polynomial sigma
 *
 * See function hqcv5_256_fft for more details.
 *
 * @param[out] error Array of 2^hqcv5_256_PARAM_M elements receiving the error polynomial
 * @param[in] sigma Array of 2^hqcv5_256_PARAM_FFT elements storing the error locator polynomial
 */
static void hqcv5_256_compute_roots(uint8_t *error, uint16_t *sigma) {
    uint16_t w[1 << hqcv5_256_PARAM_M] = {0};

    hqcv5_256_fft(w, sigma, hqcv5_256_PARAM_DELTA + 1);
    hqcv5_256_fft_retrieve_error_poly(error, w);
}

/**
 * @brief Computes the polynomial z(x)
 *
 * See @cite lin1983error (Chapter 6 - BCH Codes) for more details.
 *
 * @param[out] z Array of hqcv5_256_PARAM_DELTA + 1 elements receiving the polynomial z(x)
 * @param[in] sigma Array of 2^hqcv5_256_PARAM_FFT elements storing the error locator polynomial
 * @param[in] degree Integer that is the degree of polynomial sigma
 * @param[in] syndromes Array of 2 * hqcv5_256_PARAM_DELTA storing the syndromes
 */
static void hqcv5_256_compute_z_poly(uint16_t *z, const uint16_t *sigma, const uint16_t degree, const uint16_t *syndromes) {
    size_t i, j;
    uint16_t mask;

    z[0] = 1;

    for (i = 1; i < hqcv5_256_PARAM_DELTA + 1; ++i) {
        mask = -((uint16_t)(i - degree - 1) >> 15);
        z[i] = mask & sigma[i];
    }

    z[1] ^= syndromes[0];

    for (i = 2; i <= hqcv5_256_PARAM_DELTA; ++i) {
        mask = -((uint16_t)(i - degree - 1) >> 15);
        z[i] ^= mask & syndromes[i - 1];

        for (j = 1; j < i; ++j) {
            z[i] ^= mask & hqcv5_256_gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }
}

/**
 * @brief Computes the error values
 *
 * See @cite lin1983error (Chapter 6 - BCH Codes) for more details.
 *
 * @param[out] error_values Array of hqcv5_256_PARAM_DELTA elements receiving the error values
 * @param[in] z Array of hqcv5_256_PARAM_DELTA + 1 elements storing the polynomial z(x)
 * @param[in] error Array storing the error
 */
static void hqcv5_256_compute_error_values(uint16_t *error_values, const uint16_t *z, const uint8_t *error) {
    uint16_t beta_j[hqcv5_256_PARAM_DELTA] = {0};
    uint16_t e_j[hqcv5_256_PARAM_DELTA] = {0};

    uint16_t delta_counter;
    uint16_t delta_real_value;
    uint16_t found;
    uint16_t mask1;
    uint16_t mask2;
    uint16_t tmp1;
    uint16_t tmp2;
    uint16_t inverse;
    uint16_t inverse_power_j;

    // Compute the beta_{j_i} page 31 of the documentation
    delta_counter = 0;
    for (size_t i = 0; i < hqcv5_256_PARAM_N1; i++) {
        found = 0;
        mask1 = (uint16_t)(-((int32_t)error[i]) >> 31);  // error[i] != 0
        for (size_t j = 0; j < hqcv5_256_PARAM_DELTA; j++) {
            mask2 = ~((uint16_t)(-((int32_t)j ^ delta_counter) >> 31));  // j == delta_counter
            beta_j[j] += mask1 & mask2 & hqcv5_256_gf_exp[i];
            found += mask1 & mask2 & 1;
        }
        delta_counter += found;
    }
    delta_real_value = delta_counter;

    // Compute the e_{j_i} page 31 of the documentation
    for (size_t i = 0; i < hqcv5_256_PARAM_DELTA; ++i) {
        tmp1 = 1;
        tmp2 = 1;
        inverse = hqcv5_256_gf_inverse(beta_j[i]);
        inverse_power_j = 1;

        for (size_t j = 1; j <= hqcv5_256_PARAM_DELTA; ++j) {
            inverse_power_j = hqcv5_256_gf_mul(inverse_power_j, inverse);
            tmp1 ^= hqcv5_256_gf_mul(inverse_power_j, z[j]);
        }
        for (size_t k = 1; k < hqcv5_256_PARAM_DELTA; ++k) {
            tmp2 = hqcv5_256_gf_mul(tmp2, (1 ^ hqcv5_256_gf_mul(inverse, beta_j[(i + k) % hqcv5_256_PARAM_DELTA])));
        }
        mask1 = (uint16_t)(((int16_t)i - delta_real_value) >> 15);  // i < delta_real_value
        e_j[i] = mask1 & hqcv5_256_gf_mul(tmp1, hqcv5_256_gf_inverse(tmp2));
    }

    // Place the delta e_{j_i} values at the right coordinates of the output vector
    delta_counter = 0;
    for (size_t i = 0; i < hqcv5_256_PARAM_N1; ++i) {
        found = 0;
        mask1 = (uint16_t)(-((int32_t)error[i]) >> 31);  // error[i] != 0
        for (size_t j = 0; j < hqcv5_256_PARAM_DELTA; j++) {
            mask2 = ~((uint16_t)(-((int32_t)j ^ delta_counter) >> 31));  // j == delta_counter
            error_values[i] += mask1 & mask2 & e_j[j];
            found += mask1 & mask2 & 1;
        }
        delta_counter += found;
    }
}

/**
 * @brief Correct the errors
 *
 * @param[out] cdw Array of hqcv5_256_PARAM_N1 elements receiving the corrected vector
 * @param[in] error_values Array of hqcv5_256_PARAM_DELTA elements storing the error values
 */
static void hqcv5_256_correct_errors(uint8_t *cdw, const uint16_t *error_values) {
    for (size_t i = 0; i < hqcv5_256_PARAM_N1; ++i) {
        cdw[i] ^= error_values[i];
    }
}

/**
 * @brief Decodes the received word
 *
 * This function relies on six steps:
 * -# Compute the 2·PARAM_DELTA syndromes.
 * -# Compute the error-locator polynomial σ(x).
 * -# Use an additive FFT to find the roots of σ(x) (the error locations) and take their inverses.
 * -# Compute the error-evaluator polynomial z(x).
 * -# Compute the error values at each located position.
 * -# Correct the received polynomial by subtracting the error values.
 *
 * For a more complete picture on Reed-Solomon decoding, see Shu. Lin and Daniel J. Costello in Error Control Coding:
 * Fundamentals and Applications @cite lin1983error
 *
 * @param[out] msg Array of size VEC_K_SIZE_64 receiving the decoded message
 * @param[in] cdw Array of size hqcv5_256_VEC_N1_SIZE_64 storing the received word
 */
void hqcv5_256_reed_solomon_decode(uint64_t *msg, uint64_t *cdw) {
    uint8_t cdw_bytes[hqcv5_256_PARAM_N1] = {0};
    uint16_t syndromes[2 * hqcv5_256_PARAM_DELTA] = {0};
    uint16_t sigma[1 << hqcv5_256_PARAM_FFT] = {0};
    uint8_t error[1 << hqcv5_256_PARAM_M] = {0};
    uint16_t z[hqcv5_256_PARAM_N1] = {0};
    uint16_t error_values[hqcv5_256_PARAM_N1] = {0};
    uint16_t deg;

    // Copy the vector in an array of bytes
    memcpy(cdw_bytes, cdw, hqcv5_256_PARAM_N1);

    // Calculate the 2*hqcv5_256_PARAM_DELTA syndromes
    hqcv5_256_compute_syndromes(syndromes, cdw_bytes);

    // Compute the error locator polynomial sigma
    // Sigma's degree is at most hqcv5_256_PARAM_DELTA but the FFT requires the extra room
    deg = hqcv5_256_compute_elp(sigma, syndromes);

    // Compute the error polynomial error
    hqcv5_256_compute_roots(error, sigma);

    // Compute the polynomial z(x)
    hqcv5_256_compute_z_poly(z, sigma, deg, syndromes);

    // Compute the error values
    hqcv5_256_compute_error_values(error_values, z, error);

    // Correct the errors
    hqcv5_256_correct_errors(cdw_bytes, error_values);

    // Retrieve the message from the decoded codeword
    memcpy(msg, cdw_bytes + (hqcv5_256_PARAM_G - 1), hqcv5_256_PARAM_K);

#ifdef VERBOSE
    printf("\n\nThe syndromes: ");
    for (size_t i = 0; i < 2 * hqcv5_256_PARAM_DELTA; ++i) {
        printf("%u ", syndromes[i]);
    }
    printf("\n\nThe error locator polynomial: sigma(x) = ");
    bool first_coeff = true;
    if (sigma[0]) {
        printf("%u", sigma[0]);
        first_coeff = false;
    }
    for (size_t i = 1; i < (1 << hqcv5_256_PARAM_FFT); ++i) {
        if (sigma[i] == 0)
            continue;
        if (!first_coeff)
            printf(" + ");
        first_coeff = false;
        if (sigma[i] != 1)
            printf("%u ", sigma[i]);
        if (i == 1)
            printf("x");
        else
            printf("x^%zu", i);
    }
    if (first_coeff)
        printf("0");

    printf("\n\nThe polynomial: z(x) = ");
    bool first_coeff_1 = true;
    if (z[0]) {
        printf("%u", z[0]);
        first_coeff_1 = false;
    }
    for (size_t i = 1; i < (hqcv5_256_PARAM_DELTA + 1); ++i) {
        if (z[i] == 0)
            continue;
        if (!first_coeff_1)
            printf(" + ");
        first_coeff_1 = false;
        if (z[i] != 1)
            printf("%u ", z[i]);
        if (i == 1)
            printf("x");
        else
            printf("x^%zu", i);
    }
    if (first_coeff_1)
        printf("0");

    printf("\n\nThe pairs of (error locator numbers, error values): ");
    size_t j = 0;
    for (size_t i = 0; i < hqcv5_256_PARAM_N1; ++i) {
        if (error[i]) {
            printf("(%zu, %d) ", i, error_values[j]);
            j++;
        }
    }
    printf("\n");
#endif

    // Zeroize sensitive data
    hqcv5_256_memset_zero(cdw_bytes, sizeof cdw_bytes);
}
