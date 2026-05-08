/**
 * @file reed_muller.h
 * @brief Header file of reed_muller.c
 */

#ifndef hqcv5_192_HQC_REED_MULLER_H
#define hqcv5_192_HQC_REED_MULLER_H

#include <stddef.h>
#include <stdint.h>
#include "parameters.h"

void hqcv5_192_reed_muller_encode(uint64_t* cdw, const uint64_t* msg);
void hqcv5_192_reed_muller_decode(uint64_t* msg, const uint64_t* cdw);

#endif  // hqcv5_192_HQC_REED_MULLER_H
