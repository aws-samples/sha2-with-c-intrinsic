// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// An implementation of the compress function of SHA256 using AARCH64 SHA
// extension It was translated from assembly (OpenSSL) to C by
//
// Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

#include "neon_defs.h"
#include "sha256_defs.h"

_INLINE_ void load_data(uint32x4_t ms[4], const uint8_t *data)
{
  uint8x16x4_t d = vld1q_u8_x4(data);
  ms[0]          = vreinterpretq_u32_u8(vrev32q_u8(d.val[0]));
  ms[1]          = vreinterpretq_u32_u8(vrev32q_u8(d.val[1]));
  ms[2]          = vreinterpretq_u32_u8(vrev32q_u8(d.val[2]));
  ms[3]          = vreinterpretq_u32_u8(vrev32q_u8(d.val[3]));
}

_INLINE_ void rotate_ms(uint32x4_t ms[4])
{
  uint32x4_t tmp = ms[0];
  ms[0]          = ms[1];
  ms[1]          = ms[2];
  ms[2]          = ms[3];
  ms[3]          = tmp;
}

void sha256_compress_aarch64_sha_ext(IN OUT sha256_state_t *state,
                                     IN const uint8_t *data,
                                     IN size_t         blocks_num)
{
  uint32x4_t   ms[4];
  uint32x4_t   tmp[3];
  uint32x4x2_t st;
  uint32x4x2_t st_save;

  st = vld1q_u32_x2(state->w);

  for(size_t j = 0; j < blocks_num; j++) {
    // Save current state
    st_save = st;

    load_data(ms, data);

    tmp[0] = vaddq_u32(ms[0], vld1q_u32(&K256[0]));

    // Rounds 0-47
    PRAGMA_LOOP_UNROLL_12

    for(size_t i = 0; i < 12; i++) {
      ms[0]     = vsha256su0q_u32(ms[0], ms[1]);
      tmp[2]    = st.val[0];
      tmp[1]    = vaddq_u32(ms[1], vld1q_u32(&K256[4 * (i + 1)]));
      st.val[0] = vsha256hq_u32(st.val[0], st.val[1], tmp[0]);
      st.val[1] = vsha256h2q_u32(st.val[1], tmp[2], tmp[0]);
      ms[0]     = vsha256su1q_u32(ms[0], ms[2], ms[3]);

      rotate_ms(ms);

      uint32x4_t t = tmp[0];
      tmp[0]       = tmp[1];
      tmp[1]       = t;
    }

    // Rounds 48-51
    PRAGMA_LOOP_UNROLL_4

    for(size_t i = 0; i < 3; i++) {
      tmp[2] = st.val[0];
      tmp[LSB1(i + 1)] =
        vaddq_u32(ms[LSB2(i + 1)], vld1q_u32(&K256[4 * (i + 13)]));
      st.val[0] = vsha256hq_u32(st.val[0], st.val[1], tmp[LSB1(i)]);
      st.val[1] = vsha256h2q_u32(st.val[1], tmp[2], tmp[LSB1(i)]);
    }

    // Rounds 60-63
    tmp[2]    = st.val[0];
    st.val[0] = vsha256hq_u32(st.val[0], st.val[1], tmp[1]);
    st.val[1] = vsha256h2q_u32(st.val[1], tmp[2], tmp[1]);

    // Accumluate state
    st.val[0] = vaddq_u32(st.val[0], st_save.val[0]);
    st.val[1] = vaddq_u32(st.val[1], st_save.val[1]);

    data += SHA256_BLOCK_BYTE_LEN;
  }

  // Store state
  vst1q_u32_x2(state->w, st);
}
