// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "sha.h"

typedef uint64_t sha512_word_t;

#define SHA512_BLOCK_BYTE_LEN  128
#define SHA512_ROUNDS_NUM      80
#define SHA512_MSG_END_SYMBOL  (0x80)
#define SHA512_HASH_WORDS_NUM  (SHA512_HASH_BYTE_LEN / sizeof(sha512_word_t))
#define SHA512_BLOCK_WORDS_NUM (SHA512_BLOCK_BYTE_LEN / sizeof(sha512_word_t))

#define SHA512_FINAL_ROUND_START_IDX 64

// The SHA state: parameters a-h
typedef struct sha512_state_st {
  ALIGN(64) sha512_word_t w[SHA512_HASH_WORDS_NUM];
} sha512_state_t;

typedef struct sha512_msg_schedule_st {
  ALIGN(64) sha512_word_t w[SHA512_BLOCK_WORDS_NUM];
} sha512_msg_schedule_t;

#define Sigma0_0 28
#define Sigma0_1 34
#define Sigma0_2 39
#define Sigma1_0 14
#define Sigma1_1 18
#define Sigma1_2 41

#define sigma0_0 1
#define sigma0_1 8
#define sigma0_2 7
#define sigma1_0 19
#define sigma1_1 61
#define sigma1_2 6

#define DUP2(x, y) x, y, x, y             // NOLINT
#define DUP4(x, y) x, y, x, y, x, y, x, y // NOLINT

#define ROTR(x, v)   ROTR64(x, v)
#define Sigma0(x)    (ROTR(x, Sigma0_0) ^ ROTR(x, Sigma0_1) ^ ROTR(x, Sigma0_2))
#define Sigma1(x)    (ROTR(x, Sigma1_0) ^ ROTR(x, Sigma1_1) ^ ROTR(x, Sigma1_2))
#define sigma0(x)    (ROTR(x, sigma0_0) ^ ROTR(x, sigma0_1) ^ ((x) >> sigma0_2))
#define sigma1(x)    (ROTR(x, sigma1_0) ^ ROTR(x, sigma1_1) ^ ((x) >> sigma1_2))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Ch(x, y, z)  (((x) & (y)) ^ ((~(x)) & (z)))

// In the AVX* implementations we operate on 1/2/4 blocks in parllel
// In these cases, it is faster to duplicate the same line in memory
// and load it instead of broadcasting it.
ALIGN(64) extern const sha512_word_t K512[SHA512_ROUNDS_NUM];
ALIGN(64) extern const sha512_word_t K512x2[2 * SHA512_ROUNDS_NUM];
ALIGN(64) extern const sha512_word_t K512x4[4 * SHA512_ROUNDS_NUM];

#define ROTATE_STATE(s)                  \
  do {                                   \
    const sha512_word_t tmp = (s)->w[7]; \
    (s)->w[7]               = (s)->w[6]; \
    (s)->w[6]               = (s)->w[5]; \
    (s)->w[5]               = (s)->w[4]; \
    (s)->w[4]               = (s)->w[3]; \
    (s)->w[3]               = (s)->w[2]; \
    (s)->w[2]               = (s)->w[1]; \
    (s)->w[1]               = (s)->w[0]; \
    (s)->w[0]               = tmp;       \
  } while(0)

_INLINE_ void sha_round(IN OUT sha512_state_t *s,
                        IN const sha512_word_t x,
                        IN const sha512_word_t k)
{
  sha512_word_t t = x + s->w[7] + Sigma1(s->w[4]);

  t += Ch(s->w[4], s->w[5], s->w[6]) + k;
  s->w[7] = t + Sigma0(s->w[0]) + Maj(s->w[0], s->w[1], s->w[2]);
  s->w[3] += t;
  ROTATE_STATE(s);
}

_INLINE_ void accumulate_state(IN OUT sha512_state_t *dst,
                               IN const sha512_state_t *src)
{
  for(size_t i = 0; i < SHA512_HASH_WORDS_NUM; i++) {
    dst->w[i] += src->w[i];
  }
}

void sha512_compress_generic(IN OUT sha512_state_t *state,
                             IN const uint8_t *data,
                             IN size_t         blocks_num);

#if defined(X86_64)
void sha512_compress_x86_64_avx(IN OUT sha512_state_t *state,
                                IN const uint8_t *data,
                                IN size_t         blocks_num);

void sha512_compress_x86_64_avx2(IN OUT sha512_state_t *state,
                                 IN const uint8_t *data,
                                 IN size_t         blocks_num);

void sha512_compress_x86_64_avx512(IN OUT sha512_state_t *state,
                                   IN const uint8_t *data,
                                   IN size_t         blocks_num);
#endif // X86_64

// This ASM code was borrowed from OpenSSL as is.
extern void sha512_block_data_order_local(IN OUT sha512_word_t *state,
                                          IN const uint8_t *data,
                                          IN size_t         blocks_num);
