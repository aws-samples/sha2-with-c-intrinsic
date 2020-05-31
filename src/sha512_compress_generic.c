// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "sha512_defs.h"

// In the generic implementation we use memcpy to avoid align issues
_INLINE_ sha512_word_t load_be64(IN const void *ptr)
{
  sha512_word_t ret;
  my_memcpy(&ret, ptr, sizeof(ret));
  return bswap_64(ret);
}

_INLINE_ void load_data_and_rounds_00_15(OUT sha512_msg_schedule_t *ms,
                                         IN OUT sha512_state_t *cur_state,
                                         IN const uint8_t *data)
{
  PRAGMA_LOOP_UNROLL_4

  for(size_t i = 0; i < SHA512_BLOCK_WORDS_NUM; i++) {
    ms->w[i] = load_be64(&data[sizeof(sha512_word_t) * i]);
    sha_round(cur_state, ms->w[i], K512[i]);
  }
}

_INLINE_ void rounds_16_79(IN OUT sha512_state_t *cur_state,
                           IN OUT sha512_msg_schedule_t *ms)
{
  PRAGMA_LOOP_UNROLL_64

  for(size_t i = SHA512_BLOCK_WORDS_NUM; i < SHA512_ROUNDS_NUM; i++) {
    const sha512_word_t x1  = ms->w[LSB4(i + 1)];
    const sha512_word_t x9  = ms->w[LSB4(i + 9)];
    const sha512_word_t x14 = ms->w[LSB4(i + 14)];

    ms->w[LSB4(i)] += sigma0(x1) + sigma1(x14) + x9;
    sha_round(cur_state, ms->w[LSB4(i)], K512[i]);
  }
}

void sha512_compress_generic(IN OUT sha512_state_t *state,
                             IN const uint8_t *data,
                             IN size_t         blocks_num)
{
  sha512_state_t        cur_state;
  sha512_msg_schedule_t ms;

  while(blocks_num--) {
    my_memcpy(&cur_state, state, sizeof(cur_state));

    load_data_and_rounds_00_15(&ms, &cur_state, data);
    data += SHA512_BLOCK_BYTE_LEN;

    rounds_16_79(&cur_state, &ms);
    accumulate_state(state, &cur_state);
  }

  secure_clean(&cur_state, sizeof(cur_state));
  secure_clean(&ms, sizeof(ms));
}
