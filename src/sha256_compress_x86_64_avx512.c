// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// An implementation of the compress function of SHA256 using avx512
// The implementation is based on:
// Gueron, S., Krasnov, V. Parallelizing message schedules to accelerate the
// computations of hash functions. J Cryptogr Eng 2, 241–253 (2012).
// https://doi.org/10.1007/s13389-012-0037-z
//
// Written by Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

#include "internal/avx512_defs.h"
#include "sha256_defs.h"

// This file depends on vec_t and on the macros LOAD, ADD32, ALIGNR8, SRL32,
// SLL32, SRL64 that are defined in avx512_defs.h
#include "sha256_compress_x86_64_avx_helper.c"

// Processing 4 blocks in parallel
#define MS_VEC_NUM           ((4 * SHA256_BLOCK_BYTE_LEN) / sizeof(vec_t))
#define WORDS_IN_128_BIT_VEC (16 / sizeof(sha256_word_t))
#define WORDS_IN_VEC         (sizeof(vec_t) / sizeof(sha256_word_t))

_INLINE_ void load_data(vec_t                  x[MS_VEC_NUM],
                        sha256_msg_schedule_t *ms,
                        sha256_word_t          x2_4[][SHA256_ROUNDS_NUM],
                        const uint8_t *        data)
{
  // 32 bits (4 bytes) swap masks
  const vec_t shuf_mask =
    _mm512_set_epi32(DUP4(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203));

  PRAGMA_LOOP_UNROLL_4

  for(size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos0 = (sizeof(vec_t) / 4) * i;
    const size_t pos1 = pos0 + SHA256_BLOCK_BYTE_LEN;
    const size_t pos2 = pos1 + SHA256_BLOCK_BYTE_LEN;
    const size_t pos3 = pos2 + SHA256_BLOCK_BYTE_LEN;

    LOADU4(&data[pos3], &data[pos2], &data[pos1], &data[pos0], x[i]);

    x[i]    = SHUF8(x[i], shuf_mask);
    vec_t y = ADD32(x[i], LOAD(&K256x4[16 * i]));

    STOREU4(&x2_4[2][4 * i], &x2_4[1][4 * i], &x2_4[0][4 * i], &ms->w[4 * i], y);
  }
}

_INLINE_ void rounds_0_47(sha256_state_t *       cur_state,
                          vec_t                  x[MS_VEC_NUM],
                          sha256_msg_schedule_t *ms,
                          sha256_word_t          x2_4[][SHA256_ROUNDS_NUM])
{
  const vec_t lo_mask = _mm512_set_epi32(DUP4(-1, -1, 0x0b0a0908, 0x03020100));
  const vec_t hi_mask = _mm512_set_epi32(DUP4(0x0b0a0908, 0x03020100, -1, -1));

  // The first SHA256_BLOCK_WORDS_NUM entries of K256 were loaded in
  // load_data(...).
  size_t k256_idx = 4 * SHA256_BLOCK_WORDS_NUM;

  // Rounds 0-47 (0-15, 16-31, 32-47)
  for(size_t i = 1; i < 4; i++) {

    PRAGMA_LOOP_UNROLL_4

    for(size_t j = 0; j < MS_VEC_NUM; j++) {
      const size_t pos = WORDS_IN_128_BIT_VEC * j;

      const vec_t y = sha256_update_x_avx(x, &K256x4[k256_idx], lo_mask, hi_mask);

      sha_round(cur_state, ms->w[pos + 0], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);
      sha_round(cur_state, ms->w[pos + 2], 0);
      sha_round(cur_state, ms->w[pos + 3], 0);
      const size_t idx = (k256_idx >> 2);

      STOREU4(&x2_4[2][idx], &x2_4[1][idx], &x2_4[0][idx], &ms->w[pos], y);
      k256_idx += WORDS_IN_VEC;
    }
  }
}

_INLINE_ void rounds_48_63(sha256_state_t *             cur_state,
                           const sha256_msg_schedule_t *ms)
{
  PRAGMA_LOOP_UNROLL_16

  for(size_t i = SHA256_FINAL_ROUND_START_IDX; i < SHA256_ROUNDS_NUM; i++) {
    sha_round(cur_state, ms->w[LSB4(i)], 0);
  }
}

_INLINE_ void process_extra_block(sha256_state_t *    cur_state,
                                  const sha256_word_t t[SHA256_ROUNDS_NUM])
{
  PRAGMA_LOOP_UNROLL_64

  for(size_t i = 0; i < SHA256_ROUNDS_NUM; i++) {
    sha_round(cur_state, t[i], 0);
  }
}

void sha256_compress_x86_64_avx512(sha256_state_t *state,
                                   const uint8_t * data,
                                   size_t          blocks_num)
{
  ALIGN(64) sha256_msg_schedule_t ms;
  ALIGN(64) sha256_word_t         x2_4[3][SHA256_ROUNDS_NUM];
  sha256_state_t                  cur_state;
  vec_t                           x[MS_VEC_NUM];

  const size_t rem = LSB2(blocks_num);
  if(rem != 0) {
    sha256_compress_x86_64_avx2(state, data, rem);
    data += rem * SHA256_BLOCK_BYTE_LEN;
    blocks_num -= rem;
  }

  // Process four blocks in parallel
  // Here blocks_num is divided by 4
  for(size_t b = blocks_num; b != 0; b -= 4) {
    my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, x2_4, data);
    data += 4 * SHA256_BLOCK_BYTE_LEN;

    // First block
    rounds_0_47(&cur_state, x, &ms, x2_4);
    rounds_48_63(&cur_state, &ms);
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
