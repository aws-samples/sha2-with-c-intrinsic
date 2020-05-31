// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// An implementation of the compress function of SHA512 using avx
// The implementation is based on:
// Gueron, S., Krasnov, V. Parallelizing message schedules to accelerate the
// computations of hash functions. J Cryptogr Eng 2, 241–253 (2012).
// https://doi.org/10.1007/s13389-012-0037-z
//
// Written by Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

#include "internal/avx_defs.h"
#include "sha512_defs.h"

// This file depends on vec_t and on the macros LOAD, ADD64, ALIGNR8, SRL64, SLL64
// that are defined in avx512_defs.h
#include "sha512_compress_x86_64_avx_helper.c"

#define MS_VEC_NUM   (SHA512_BLOCK_BYTE_LEN / sizeof(vec_t))
#define WORDS_IN_VEC (16 / sizeof(sha512_word_t))

_INLINE_ void load_data(OUT vec_t x[MS_VEC_NUM],
                        IN OUT sha512_msg_schedule_t *ms,
                        IN const uint8_t *data)
{
  // 64 bits (8 bytes) swap masks
  const vec_t shuf_mask =
    _mm_setr_epi32(0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b);

  PRAGMA_LOOP_UNROLL_8

  for(size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos = WORDS_IN_VEC * i;

    x[i] = LOAD(&data[sizeof(vec_t) * i]);
    x[i] = SHUF8(x[i], shuf_mask);
    STORE(&ms->w[pos], ADD64(x[i], LOAD(&K512[pos])));
  }
}

_INLINE_ void rounds_0_63(sha512_state_t *       cur_state,
                          vec_t                  x[MS_VEC_NUM],
                          sha512_msg_schedule_t *ms)
{
  // The first SHA512_BLOCK_WORDS_NUM entries of K512 were loaded in
  // load_data(...).
  size_t k512_idx = SHA512_BLOCK_WORDS_NUM;

  // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
  for(size_t i = 0; i < 4; i++) {

    PRAGMA_LOOP_UNROLL_8

    for(size_t j = 0; j < MS_VEC_NUM; j++) {
      const size_t pos = WORDS_IN_VEC * j;

      const vec_t y = sha512_update_x_avx(x, &K512[k512_idx]);

      sha_round(cur_state, ms->w[pos], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);

      STORE(&ms->w[pos], y);
      k512_idx += WORDS_IN_VEC;
    }
  }
}

_INLINE_ void rounds_64_79(sha512_state_t *             cur_state,
                           const sha512_msg_schedule_t *ms)
{
  PRAGMA_LOOP_UNROLL_16

  for(size_t i = SHA512_FINAL_ROUND_START_IDX; i < SHA512_ROUNDS_NUM; i++) {
    sha_round(cur_state, ms->w[LSB4(i)], 0);
  }
}

void sha512_compress_x86_64_avx(sha512_state_t *state,
                                const uint8_t * data,
                                size_t          blocks_num)
{
  sha512_state_t        cur_state;
  sha512_msg_schedule_t ms;
  vec_t                 x[MS_VEC_NUM];

  while(blocks_num--) {
    my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, data);
    data += SHA512_BLOCK_BYTE_LEN;

    rounds_0_63(&cur_state, x, &ms);
    rounds_64_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);
  }

  secure_clean(&cur_state, sizeof(cur_state));
  secure_clean(&ms, sizeof(ms));
}
