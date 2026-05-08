/**
 * @file fft.h
 * @brief Header file of fft.c
 */

#ifndef hqcv5_256_HQC_FFT_H
#define hqcv5_256_HQC_FFT_H

#include <stddef.h>
#include <stdint.h>

void hqcv5_256_fft(uint16_t *w, const uint16_t *f, size_t f_coeffs);
void hqcv5_256_fft_retrieve_error_poly(uint8_t *error, const uint16_t *w);

#endif  // hqcv5_256_HQC_FFT_H
