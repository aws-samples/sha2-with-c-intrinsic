// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include "neon_defs.h"

int main(void)
{
    uint8_t data[8*16*4];
    uint32x4_t TMP[2] = {0};

    // Check for vld1q_u8_x4 intrinsic
    uint8x16x4_t d = vld1q_u8_x4(data);
    TMP[0]            = vreinterpretq_u32_u8(vrev32q_u8(d.val[0]));

    uint8x16x2_t d0 = vld1q_u8_x2(data);
    TMP[1]           = vreinterpretq_u32_u8(vrev32q_u8(d0.val[0]));

    // Check for vsha256h2q_u32 intrinsic
    vsha256h2q_u32(TMP[0], TMP[1], TMP[0]);
}
