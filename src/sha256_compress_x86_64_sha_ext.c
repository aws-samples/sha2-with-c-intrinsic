// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// An implementation of the compress function of SHA256 using the SHA extension
// The implementation is based on:
// https://software.intel.com/en-us/articles/intel-sha-extensions
//
// Written by Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

#include "avx_defs.h"
#include "sha256_defs.h"

#define RND2(s0, s1, data) (_mm_sha256rnds2_epu32(s0, s1, data))
#define SHAMSG1(m1, m2)    (_mm_sha256msg1_epu32(m1, m2))
#define SHAMSG2(m1, m2)    (_mm_sha256msg2_epu32(m1, m2))

#define SET_K(i)                                                   \
  (SETR32(K256[4 * (i)], K256[(4 * (i)) + 1], K256[(4 * (i)) + 2], \
          K256[(4 * (i)) + 3]))

void sha256_compress_x86_64_sha_ext(IN OUT sha256_state_t *state,
                                    IN const uint8_t *data,
                                    IN size_t         blocks_num)
{
  vec_t state0;
  vec_t state1;
  vec_t msg;
  vec_t tmp;
  vec_t msgtmp[4];
  vec_t ABEF_SAVE;
  vec_t CDGH_SAVE;

  const vec_t shuf_mask =
    SET64(UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203));

  tmp    = SHUF32(LOAD(&state->w[0]), 0xB1); // CDAB
  state1 = SHUF32(LOAD(&state->w[4]), 0x1B); // EFGH
  state0 = ALIGNR8(tmp, state1, 8);          // ABEF
  state1 = BLEND16(state1, tmp, 0xF0);       // CDGH

  while(blocks_num--) {
    // Save the current state
    ABEF_SAVE = state0;
    CDGH_SAVE = state1;

    // Rounds 0-3
    msgtmp[0] = SHUF8(LOAD(&data[0]), shuf_mask);
    msg       = ADD32(msgtmp[0], SET_K(0));
    state1    = RND2(state1, state0, msg);
    msg       = SHUF32(msg, 0x0E);
    state0    = RND2(state0, state1, msg);

    PRAGMA_LOOP_UNROLL_2

    // Rounds 4-7 (i=1)
    // Rounds 8-11 (i=2)
    for(size_t i = 1; i <= 2; i++) {
      msgtmp[i]     = SHUF8(LOAD(&data[16 * i]), shuf_mask);
      msg           = ADD32(msgtmp[i], SET_K(i));
      state1        = RND2(state1, state0, msg);
      msg           = SHUF32(msg, 0x0E);
      state0        = RND2(state0, state1, msg);
      msgtmp[i - 1] = SHAMSG1(msgtmp[i - 1], msgtmp[i]);
    }

    // Rounds 12-59 in blocks of 4 (12 multi-rounds)
    msgtmp[3] = SHUF8(LOAD(&data[48]), shuf_mask);

    PRAGMA_LOOP_UNROLL_12

    for(size_t i = 3; i <= 14; i++) {
      const size_t prev = LSB2(i - 1);
      const size_t curr = LSB2(i);
      const size_t next = LSB2(i + 1);

      msg          = ADD32(msgtmp[curr], SET_K(i));
      state1       = RND2(state1, state0, msg);
      tmp          = ALIGNR8(msgtmp[curr], msgtmp[prev], 4);
      msgtmp[next] = ADD32(msgtmp[next], tmp);
      msgtmp[next] = SHAMSG2(msgtmp[next], msgtmp[curr]);
      msg          = SHUF32(msg, 0x0E);
      state0       = RND2(state0, state1, msg);
      msgtmp[prev] = SHAMSG1(msgtmp[prev], msgtmp[curr]);
    }

    // Rounds 60-63
    msg    = ADD32(msgtmp[3], SET_K(15));
    state1 = RND2(state1, state0, msg);
    msg    = SHUF32(msg, 0x0E);
    state0 = RND2(state0, state1, msg);

    // Accumulate state
    state0 = ADD32(state0, ABEF_SAVE);
    state1 = ADD32(state1, CDGH_SAVE);

    data += SHA256_BLOCK_BYTE_LEN;
  }

  tmp    = SHUF32(state0, 0x1B);       // FEBA
  state1 = SHUF32(state1, 0xB1);       // DCHG
  state0 = BLEND16(tmp, state1, 0xF0); // DCBA
  state1 = ALIGNR8(state1, tmp, 8);    // ABEF

  STORE((vec_t *)&state->w[0], state0);
  STORE((vec_t *)&state->w[4], state1);
}
