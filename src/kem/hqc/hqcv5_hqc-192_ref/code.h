/**
 * @file code.h
 * @brief Header file of code.c
 */

#ifndef hqcv5_192_HQC_CODE_H
#define hqcv5_192_HQC_CODE_H

#include <stddef.h>
#include <stdint.h>
#include "parameters.h"

void hqcv5_192_code_encode(uint64_t *em, const uint64_t *m);
void hqcv5_192_code_decode(uint64_t *m, const uint64_t *em);

#endif  // hqcv5_192_HQC_CODE_H
