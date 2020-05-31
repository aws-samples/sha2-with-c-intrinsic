// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// An implementation of the compress function of SHA512 using avx2
// The implementation is based on:
// Gueron, S., Krasnov, V. Parallelizing message schedules to accelerate the
// computations of hash functions. J Cryptogr Eng 2, 241–253 (2012).
// https://doi.org/10.1007/s13389-012-0037-z
//
// Written by Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

#include "internal/avx2_defs.h"
#include "sha512_defs.h"

// This file depends on vec_t and on the macros LOAD, ADD64, ALIGNR8, SRL64, SLL64
// that are defined in avx512_defs.h
#include "sha512_compress_x86_64_avx_helper.c"

// Processing 2 blocks in parallel
#define MS_VEC_NUM           ((2 * SHA512_BLOCK_BYTE_LEN) / sizeof(vec_t))
#define WORDS_IN_128_BIT_VEC (16 / sizeof(sha512_word_t))
#define WORDS_IN_VEC         (sizeof(vec_t) / sizeof(sha512_word_t))

_INLINE_ void load_data(vec_t                  x[MS_VEC_NUM],
                        sha512_msg_schedule_t *ms,
                        sha512_word_t          t2[SHA512_ROUNDS_NUM],
                        const uint8_t *        data)
{
  // 64 bits (8 bytes) swap masks
  const vec_t shuf_mask =
    _mm256_set_epi64x(DUP2(0x08090a0b0c0d0e0f, 0x0001020304050607));

  PRAGMA_LOOP_UNROLL_8

  for(size_t i = 0; i < MS_VEC_NUM; i++) {
    const size_t pos0 = (sizeof(vec_t) / 2) * i;
    const size_t pos1 = pos0 + SHA512_BLOCK_BYTE_LEN;

    LOADU2(&data[pos1], &data[pos0], x[i]);
    x[i]    = SHUF8(x[i], shuf_mask);
    vec_t y = ADD64(x[i], LOAD(&K512x2[4 * i]));
    STOREU2(&t2[2 * i], &ms->w[2 * i], y);
  }
}

_INLINE_ void rounds_0_63(sha512_state_t *       cur_state,
                          vec_t                  x[MS_VEC_NUM],
                          sha512_msg_schedule_t *ms,
                          sha512_word_t          t2[SHA512_ROUNDS_NUM])
{
  // The first SHA512_BLOCK_WORDS_NUM entries of K512 were loaded in
  // load_data(...).
  size_t k512_idx = 2 * SHA512_BLOCK_WORDS_NUM;

  // Rounds 0-63 (0-15, 16-31, 32-47, 48-63)
  for(size_t i = 1; i < 5; i++) {

    PRAGMA_LOOP_UNROLL_8

    for(size_t j = 0; j < 8; j++) {
      const size_t pos = WORDS_IN_128_BIT_VEC * j;

      const vec_t y = sha512_update_x_avx(x, &K512x2[k512_idx]);

      sha_round(cur_state, ms->w[pos], 0);
      sha_round(cur_state, ms->w[pos + 1], 0);
      STOREU2(&t2[(16 * i) + pos], &ms->w[pos], y);
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

_INLINE_ void process_second_block(sha512_state_t *    cur_state,
                                   const sha512_word_t t2[SHA512_ROUNDS_NUM])
{
  PRAGMA_LOOP_UNROLL_80

  for(size_t i = 0; i < SHA512_ROUNDS_NUM; i++) {
    sha_round(cur_state, t2[i], 0);
  }
}

void sha512_compress_x86_64_avx2(sha512_state_t *state,
                                 const uint8_t * data,
                                 size_t          blocks_num)
{
  ALIGN(64) sha512_msg_schedule_t ms;
  ALIGN(64) sha512_word_t         t2[SHA512_ROUNDS_NUM];
  sha512_state_t                  cur_state;
  vec_t                           x[MS_VEC_NUM];

  if(LSB1(blocks_num)) {
    sha512_compress_x86_64_avx(state, data, 1);
    data += SHA512_BLOCK_BYTE_LEN;
    blocks_num--;
  }

  // Process two blocks in parallel
  // Here blocks_num is even
  for(size_t b = blocks_num; b != 0; b -= 2) {
    my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));

    load_data(x, &ms, t2, data);
    data += 2 * SHA512_BLOCK_BYTE_LEN;

    // First block
    rounds_0_63(&cur_state, x, &ms, t2);
    rounds_64_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);

    // Second block
    my_memcpy(cur_state.w, state->w, sizeof(cur_state.w));
    process_second_block(&cur_state, t2);
    accumulate_state(state, &cur_state);
  }

  secure_clean(&cur_state, sizeof(cur_state));
  secure_clean(&ms, sizeof(ms));
  secure_clean(t2, sizeof(t2));
}
