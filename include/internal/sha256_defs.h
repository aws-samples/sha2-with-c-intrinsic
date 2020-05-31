// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "sha.h"

typedef uint32_t sha256_word_t;

#define SHA256_BLOCK_BYTE_LEN  64
#define SHA256_ROUNDS_NUM      64
#define SHA256_MSG_END_SYMBOL  (0x80)
#define SHA256_HASH_WORDS_NUM  (SHA256_HASH_BYTE_LEN / sizeof(sha256_word_t))
#define SHA256_BLOCK_WORDS_NUM (SHA256_BLOCK_BYTE_LEN / sizeof(sha256_word_t))

#define SHA256_FINAL_ROUND_START_IDX 48

// The SHA state: parameters a-h
typedef ALIGN(64) struct sha256_state_st {
  sha256_word_t w[SHA256_HASH_WORDS_NUM];
} sha256_state_t;

typedef ALIGN(64) struct sha256_msg_schedule_st {
  sha256_word_t w[SHA256_BLOCK_WORDS_NUM];
} sha256_msg_schedule_t;

#define Sigma0_0 2
#define Sigma0_1 13
#define Sigma0_2 22
#define Sigma1_0 6
#define Sigma1_1 11
#define Sigma1_2 25

#define sigma0_0 7
#define sigma0_1 18
#define sigma0_2 3
#define sigma1_0 17
#define sigma1_1 19
#define sigma1_2 10

#define DUP2(x, y, z, w) x, y, z, w, x, y, z, w                         // NOLINT
#define DUP4(x, y, z, w) x, y, z, w, x, y, z, w, x, y, z, w, x, y, z, w // NOLINT

#define ROTR(x, v)   ROTR32(x, v)
#define Sigma0(x)    (ROTR(x, Sigma0_0) ^ ROTR(x, Sigma0_1) ^ ROTR(x, Sigma0_2))
#define Sigma1(x)    (ROTR(x, Sigma1_0) ^ ROTR(x, Sigma1_1) ^ ROTR(x, Sigma1_2))
#define sigma0(x)    (ROTR(x, sigma0_0) ^ ROTR(x, sigma0_1) ^ ((x) >> sigma0_2))
#define sigma1(x)    (ROTR(x, sigma1_0) ^ ROTR(x, sigma1_1) ^ ((x) >> sigma1_2))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Ch(x, y, z)  (((x) & (y)) ^ ((~(x)) & (z)))

// In the AVX* implementations we operate on 1/2/4 blocks in parllel
// In these cases, it is faster to duplicate the same line in memory
// and load it instead of broadcasting it.
ALIGN(64) extern const sha256_word_t K256[SHA256_ROUNDS_NUM];
ALIGN(64) extern const sha256_word_t K256x2[2 * SHA256_ROUNDS_NUM];
ALIGN(64) extern const sha256_word_t K256x4[4 * SHA256_ROUNDS_NUM];

#define ROTATE_STATE(s)                  \
  do {                                   \
    const sha256_word_t tmp = (s)->w[7]; \
    (s)->w[7]               = (s)->w[6]; \
    (s)->w[6]               = (s)->w[5]; \
    (s)->w[5]               = (s)->w[4]; \
    (s)->w[4]               = (s)->w[3]; \
    (s)->w[3]               = (s)->w[2]; \
    (s)->w[2]               = (s)->w[1]; \
    (s)->w[1]               = (s)->w[0]; \
    (s)->w[0]               = tmp;       \
  } while(0)

_INLINE_ void sha_round(IN OUT sha256_state_t *s,
                        IN const sha256_word_t x,
                        IN const sha256_word_t k)
{
  sha256_word_t t = x + s->w[7] + Sigma1(s->w[4]);

  t += Ch(s->w[4], s->w[5], s->w[6]) + k;
  s->w[7] = t + Sigma0(s->w[0]) + Maj(s->w[0], s->w[1], s->w[2]);
  s->w[3] += t;
  ROTATE_STATE(s);
}

_INLINE_ void accumulate_state(IN OUT sha256_state_t *dst,
                               IN const sha256_state_t *src)
{
  for(size_t i = 0; i < SHA256_HASH_WORDS_NUM; i++) {
    dst->w[i] += src->w[i];
  }
}

void sha256_compress_generic(IN OUT sha256_state_t *state,
                             IN const uint8_t *data,
                             IN size_t         blocks_num);

#if defined(X86_64)

void sha256_compress_x86_64_avx(IN OUT sha256_state_t *state,
                                IN const uint8_t *data,
                                IN size_t         blocks_num);

void sha256_compress_x86_64_avx2(IN OUT sha256_state_t *state,
                                 IN const uint8_t *data,
                                 IN size_t         blocks_num);

void sha256_compress_x86_64_avx512(IN OUT sha256_state_t *state,
                                   IN const uint8_t *data,
                                   IN size_t         blocks_num);

void sha256_compress_x86_64_sha_ext(IN OUT sha256_state_t *state,
                                    IN const uint8_t *data,
                                    IN size_t         blocks_num);
#endif // X86_64

#if defined(AARCH64)
void sha256_compress_aarch64_sha_ext(IN OUT sha256_state_t *state,
                                     IN const uint8_t *data,
                                     IN size_t         blocks_num);
#endif

// This ASM code was borrowed from OpenSSL as is.
extern void sha256_block_data_order_local(IN OUT sha256_word_t *state,
                                          IN const uint8_t *data,
                                          IN size_t         blocks_num);
