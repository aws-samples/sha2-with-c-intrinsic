// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "sha256_defs.h"

// In the generic implementation we use memcpy to avoid align issues
_INLINE_ sha256_word_t load_be32(IN const void *ptr)
{
  sha256_word_t ret;
  my_memcpy(&ret, ptr, sizeof(ret));
  return bswap_32(ret);
}

_INLINE_ void load_data_and_rounds_00_15(OUT sha256_msg_schedule_t *ms,
                                         IN OUT sha256_state_t *cur_state,
                                         IN const uint8_t *data)
{
  PRAGMA_LOOP_UNROLL_4

  for(size_t i = 0; i < SHA256_BLOCK_WORDS_NUM; i++) {
    ms->w[i] = load_be32(&data[sizeof(sha256_word_t) * i]);
    sha_round(cur_state, ms->w[i], K256[i]);
  }
}

_INLINE_ void rounds_16_63(IN OUT sha256_state_t *cur_state,
                           IN OUT sha256_msg_schedule_t *ms)
{
  PRAGMA_LOOP_UNROLL_48

  for(size_t i = SHA256_BLOCK_WORDS_NUM; i < SHA256_ROUNDS_NUM; i++) {
    const sha256_word_t x1  = ms->w[LSB4(i + 1)];
    const sha256_word_t x9  = ms->w[LSB4(i + 9)];
    const sha256_word_t x14 = ms->w[LSB4(i + 14)];

    ms->w[LSB4(i)] += sigma0(x1) + sigma1(x14) + x9;
    sha_round(cur_state, ms->w[LSB4(i)], K256[i]);
  }
}

void sha256_compress_generic(IN OUT sha256_state_t *state,
                             IN const uint8_t *data,
                             IN size_t         blocks_num)
{
  sha256_state_t        cur_state;
  sha256_msg_schedule_t ms;

  while(blocks_num--) {
    my_memcpy(&cur_state, state, sizeof(cur_state));

    load_data_and_rounds_00_15(&ms, &cur_state, data);
    data += SHA256_BLOCK_BYTE_LEN;

    rounds_16_63(&cur_state, &ms);
    accumulate_state(state, &cur_state);
  }

  secure_clean(&cur_state, sizeof(cur_state));
  secure_clean(&ms, sizeof(ms));
}
