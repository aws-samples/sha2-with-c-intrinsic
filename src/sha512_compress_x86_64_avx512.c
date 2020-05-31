// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// An implementation of the compress function of SHA512 using avx512
// The implementation is based on:
// Gueron, S., Krasnov, V. Parallelizing message schedules to accelerate the
// computations of hash functions. J Cryptogr Eng 2, 241–253 (2012).
// https://doi.org/10.1007/s13389-012-0037-z
//
// Written by Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

#include "internal/avx512_defs.h"
#include "sha512_defs.h"

// This file depends on vec_t and on the macros LOAD, ADD64, ALIGNR8, SRL64, SLL64
// that are defined in avx512_defs.h
#include "sha512_compress_x86_64_avx_helper.c"

// Processing 4 blocks in parallel
#define MS_VEC_NUM           ((4 * SHA512_BLOCK_BYTE_LEN) / sizeof(vec_t))
#define WORDS_IN_128_BIT_VEC (16 / sizeof(sha512_word_t))
#define WORDS_IN_VEC         (sizeof(vec_t) / sizeof(sha512_word_t))

_INLINE_ void load_data(vec_t                  x[MS_VEC_NUM],
                        sha512_msg_schedule_t *ms,
                        sha512_word_t          x2_4[][SHA512_ROUNDS_NUM],
                        const uint8_t *        data)
{
  // 64 bits (8 bytes) swap masks
  const vec_t shuf_mask =
    _mm512_set_epi64(DUP4(0x08090a0b0c0d0e0f, 0x0001020304050607));

  PRAGMA_LOOP_UNROLL_8

  for(size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos0 = (sizeof(vec_t) / 4) * i;
    const size_t pos1 = pos0 + SHA512_BLOCK_BYTE_LEN;
    const size_t pos2 = pos1 + SHA512_BLOCK_BYTE_LEN;
    const size_t pos3 = pos2 + SHA512_BLOCK_BYTE_LEN;
    LOADU4(&data[pos3], &data[pos2], &data[pos1], &data[pos0], x[i]);

    x[i]    = SHUF8(x[i], shuf_mask);
    vec_t y = ADD64(x[i], LOAD(&K512x4[8 * i]));

    STOREU4(&x2_4[2][2 * i], &x2_4[1][2 * i], &x2_4[0][2 * i], &ms->w[2 * i], y);
  }
}

_INLINE_ void rounds_0_63(sha512_state_t *       cur_state,
                          vec_t                  x[MS_VEC_NUM],
                          sha512_msg_schedule_t *ms,
                          sha512_word_t          x2_4[][SHA512_ROUNDS_NUM])
{
  // The first SHA512_BLOCK_WORDS_NUM entries of K512 were loaded in
  // load_data(...).
  size_t k512_idx = 4 * SHA512_BLOCK_WORDS_NUM;

  // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
  for(size_t i = 1; i < 5; i++) {

    PRAGMA_LOOP_UNROLL_8

    for(size_t j = 0; j < MS_VEC_NUM; j++) {
      const size_t pos = WORDS_IN_128_BIT_VEC * j;
      const vec_t  y   = sha512_update_x_avx(x, &K512x4[k512_idx]);

      sha_round(cur_state, ms->w[pos], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);
      const size_t idx = k512_idx >> 2;

      STOREU4(&x2_4[2][idx], &x2_4[1][idx], &x2_4[0][idx], &ms->w[pos], y);
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

_INLINE_ void process_extra_block(sha512_state_t *    cur_state,
                                  const sha512_word_t t[SHA512_ROUNDS_NUM])
{
  PRAGMA_LOOP_UNROLL_80

  for(size_t i = 0; i < SHA512_ROUNDS_NUM; i++) {
    sha_round(cur_state, t[i], 0);
  }
}

void sha512_compress_x86_64_avx512(sha512_state_t *state,
                                   const uint8_t * data,
                                   size_t          blocks_num)
{
  ALIGN(64) sha512_msg_schedule_t ms;
  ALIGN(64) sha512_word_t         x2_4[3][SHA512_ROUNDS_NUM];
  sha512_state_t                  cur_state;
  vec_t                           x[MS_VEC_NUM];

  const size_t rem = LSB2(blocks_num);
  if(rem != 0) {
    sha512_compress_x86_64_avx2(state, data, rem);
    data += rem * SHA512_BLOCK_BYTE_LEN;
    blocks_num -= rem;
  }

  // Process four blocks in parallel
  // Here blocks_num is divided by 4
  for(size_t b = blocks_num; b != 0; b -= 4) {
    my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, x2_4, data);
    data += 4 * SHA512_BLOCK_BYTE_LEN;

    // First block
    rounds_0_63(&cur_state, x, &ms, x2_4);
    rounds_64_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);

    for(size_t i = 0; i <= 2; i++) {
      my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
      process_extra_block(&cur_state, x2_4[i]);
      accumulate_state(state, &cur_state);
    }
  }

  secure_clean(&cur_state, sizeof(cur_state));
  secure_clean(&ms, sizeof(ms));
  secure_clean(x2_4, sizeof(x2_4));
}
