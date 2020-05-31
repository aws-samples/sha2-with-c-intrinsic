// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#if defined(__ARM_NEON)
#  include <arm_neon.h>
#endif

#if !defined(__clang__)
static inline uint8x16x4_t vld1q_u8_x4(const uint8_t *mem)
{
  uint8x16x2_t d0 = vld1q_u8_x2(mem);
  uint8x16x2_t d1 = vld1q_u8_x2(&mem[32]);

  uint8x16x4_t ret;
  ret.val[0] = d0.val[0];
  ret.val[1] = d0.val[1];
  ret.val[2] = d1.val[0];
  ret.val[3] = d1.val[1];
  return ret;
}

static inline void vst1q_u32_x2(uint32_t *mem, const uint32x4x2_t v)
{
  vst1q_u32(mem, v.val[0]);
  vst1q_u32(mem + 4, v.val[1]);
}
#endif // __clang__
