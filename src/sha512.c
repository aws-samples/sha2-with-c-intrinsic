// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>

#include "sha512_defs.h"

#define LAST_BLOCK_BYTE_LEN (2 * SHA512_BLOCK_BYTE_LEN)

typedef struct sha512_hash_s {
  ALIGN(64) sha512_state_t state;
  uint64_t len;

  ALIGN(64) uint8_t data[LAST_BLOCK_BYTE_LEN];

  sha512_word_t rem;
  sha_impl_t    impl;
} sha512_ctx_t;

_INLINE_ void sha512_init(OUT sha512_ctx_t *ctx)
{
  ctx->state.w[0] = UINT64_C(0x6a09e667f3bcc908);
  ctx->state.w[1] = UINT64_C(0xbb67ae8584caa73b);
  ctx->state.w[2] = UINT64_C(0x3c6ef372fe94f82b);
  ctx->state.w[3] = UINT64_C(0xa54ff53a5f1d36f1);
  ctx->state.w[4] = UINT64_C(0x510e527fade682d1);
  ctx->state.w[5] = UINT64_C(0x9b05688c2b3e6c1f);
  ctx->state.w[6] = UINT64_C(0x1f83d9abfb41bd6b);
  ctx->state.w[7] = UINT64_C(0x5be0cd19137e2179);
}

_INLINE_ void sha512_compress(IN OUT sha512_ctx_t *ctx,
                              IN const uint8_t *data,
                              IN const size_t   blocks_num)
{
  assert((ctx != NULL) && (data != NULL));

  // OpenSSL code can crash without this check
  if(blocks_num == 0) {
    return;
  }

  switch(ctx->impl) {
#if defined(X86_64)
    case AVX_IMPL:
      sha512_compress_x86_64_avx(&ctx->state, data, blocks_num);
      break;

    case OPENSSL_AVX_IMPL:
      RUN_OPENSSL_CODE_WITH_AVX(
        sha512_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

#if defined(AVX2_SUPPORT)
    case AVX2_IMPL:
      sha512_compress_x86_64_avx2(&ctx->state, data, blocks_num);
      break;

    case OPENSSL_AVX2_IMPL:
      RUN_OPENSSL_CODE_WITH_AVX2(
        sha512_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

#if defined(AVX512_SUPPORT)
    case AVX512_IMPL:
      sha512_compress_x86_64_avx512(&ctx->state, data, blocks_num);
      break;
#endif

#if defined(NEON_SUPPORT)
    case OPENSSL_NEON_IMPL:
      RUN_OPENSSL_CODE_WITH_NEON(
        sha512_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

    default: sha512_compress_generic(&ctx->state, data, blocks_num); break;
  }
}

_INLINE_ void sha512_update(IN OUT sha512_ctx_t *ctx,
                            IN const uint8_t *data,
                            IN size_t         byte_len)
{
  // On exiting this function ctx->rem < SHA512_BLOCK_BYTE_LEN

  assert((ctx != NULL) && (data != NULL));

  if(byte_len == 0) {
    return;
  }

  // Accumulate the overall size
  ctx->len += byte_len;

  // Less than a block. Store the data in a temporary buffer
  if((ctx->rem != 0) && (ctx->rem + byte_len < SHA512_BLOCK_BYTE_LEN)) {
    my_memcpy(&ctx->data[ctx->rem], data, byte_len);
    ctx->rem += byte_len;
    return;
  }

  // Complete and compress a previously stored block
  if(ctx->rem != 0) {
    const size_t clen = SHA512_BLOCK_BYTE_LEN - ctx->rem;
    my_memcpy(&ctx->data[ctx->rem], data, clen);
    sha512_compress(ctx, ctx->data, 1);

    data += clen;
    byte_len -= clen;

    ctx->rem = 0;
    secure_clean(ctx->data, SHA512_BLOCK_BYTE_LEN);
  }

  // Compress full blocks
  if(byte_len >= SHA512_BLOCK_BYTE_LEN) {
    const size_t blocks_num           = (byte_len >> 7);
    const size_t full_blocks_byte_len = (blocks_num << 7);

    sha512_compress(ctx, data, blocks_num);

    data += full_blocks_byte_len;
    byte_len -= full_blocks_byte_len;
  }

  // Store the reminder
  my_memcpy(ctx->data, data, byte_len);
  ctx->rem = byte_len;
}

_INLINE_ void sha512_final(OUT uint8_t *dgst, IN OUT sha512_ctx_t *ctx)
{
  assert((ctx != NULL) && (dgst != NULL));
  assert(ctx->rem < SHA512_BLOCK_BYTE_LEN);

  // Byteswap the length in bits of the hashed message
  const uint64_t bswap_len      = bswap_64(8 * ctx->len);
  const size_t   last_block_num = (ctx->rem < 112) ? 1 : 2;
  const size_t   last_qw_pos =
    (last_block_num * SHA512_BLOCK_BYTE_LEN) - sizeof(bswap_len);

  ctx->data[ctx->rem++] = SHA512_MSG_END_SYMBOL;

  // Reset the rest of the data buffer
  my_memset(&ctx->data[ctx->rem], 0, sizeof(ctx->data) - ctx->rem);
  my_memcpy(&ctx->data[last_qw_pos], (const uint8_t *)&bswap_len,
            sizeof(bswap_len));

  // Compress the final block
  sha512_compress(ctx, ctx->data, last_block_num);

  // This implementation assumes running on a Little endian machine
  ctx->state.w[0] = bswap_64(ctx->state.w[0]);
  ctx->state.w[1] = bswap_64(ctx->state.w[1]);
  ctx->state.w[2] = bswap_64(ctx->state.w[2]);
  ctx->state.w[3] = bswap_64(ctx->state.w[3]);
  ctx->state.w[4] = bswap_64(ctx->state.w[4]);
  ctx->state.w[5] = bswap_64(ctx->state.w[5]);
  ctx->state.w[6] = bswap_64(ctx->state.w[6]);
  ctx->state.w[7] = bswap_64(ctx->state.w[7]);
  my_memcpy(dgst, ctx->state.w, SHA512_HASH_BYTE_LEN);

  secure_clean(ctx, sizeof(*ctx));
}

void sha512(OUT uint8_t *dgst,
            IN const uint8_t *  data,
            IN const size_t     byte_len,
            IN const sha_impl_t impl)
{
  assert((data != NULL) || (dgst != NULL));

  sha512_ctx_t ctx = {0};
  ctx.impl         = impl;
  sha512_init(&ctx);
  sha512_update(&ctx, data, byte_len);
  sha512_final(dgst, &ctx);
}
