// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>

#include "sha256_defs.h"

#define LAST_BLOCK_BYTE_LEN (2 * SHA256_BLOCK_BYTE_LEN)

typedef struct sha256_hash_s {
  ALIGN(64) sha256_state_t state;
  uint64_t len;

  ALIGN(64) uint8_t data[LAST_BLOCK_BYTE_LEN];

  sha256_word_t rem;
  sha_impl_t    impl;
} sha256_ctx_t;

_INLINE_ void sha256_init(OUT sha256_ctx_t *ctx)
{
  ctx->state.w[0] = UINT32_C(0x6a09e667);
  ctx->state.w[1] = UINT32_C(0xbb67ae85);
  ctx->state.w[2] = UINT32_C(0x3c6ef372);
  ctx->state.w[3] = UINT32_C(0xa54ff53a);
  ctx->state.w[4] = UINT32_C(0x510e527f);
  ctx->state.w[5] = UINT32_C(0x9b05688c);
  ctx->state.w[6] = UINT32_C(0x1f83d9ab);
  ctx->state.w[7] = UINT32_C(0x5be0cd19);
}

_INLINE_ void sha256_compress(IN OUT sha256_ctx_t *ctx,
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
      sha256_compress_x86_64_avx(&ctx->state, data, blocks_num);
      break;

    case OPENSSL_AVX_IMPL:
      RUN_OPENSSL_CODE_WITH_AVX(
        sha256_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

#if defined(AVX2_SUPPORT)
    case AVX2_IMPL:
      sha256_compress_x86_64_avx2(&ctx->state, data, blocks_num);
      break;

    case OPENSSL_AVX2_IMPL:
      RUN_OPENSSL_CODE_WITH_AVX2(
        sha256_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

#if defined(AVX512_SUPPORT)
    case AVX512_IMPL:
      sha256_compress_x86_64_avx512(&ctx->state, data, blocks_num);
      break;
#endif

#if defined(X86_64_SHA_SUPPORT)
    case SHA_EXT_IMPL:
      sha256_compress_x86_64_sha_ext(&ctx->state, data, blocks_num);
      break;

    case OPENSSL_SHA_EXT_IMPL:
      RUN_OPENSSL_CODE_WITH_SHA_EXT(
        sha256_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

#if defined(NEON_SUPPORT)
    case OPENSSL_NEON_IMPL:
      RUN_OPENSSL_CODE_WITH_NEON(
        sha256_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif

#if defined(AARCH64_SHA_SUPPORT)
    case SHA_EXT_IMPL:
      sha256_compress_aarch64_sha_ext(&ctx->state, data, blocks_num);
      break;

    case OPENSSL_SHA_EXT_IMPL:
      RUN_OPENSSL_CODE_WITH_SHA256_EXT(
        sha256_block_data_order_local(ctx->state.w, data, blocks_num););
      break;
#endif
    default: sha256_compress_generic(&ctx->state, data, blocks_num); break;
  }
}

_INLINE_ void sha256_update(IN OUT sha256_ctx_t *ctx,
                            IN const uint8_t *data,
                            IN size_t         byte_len)
{
  // On exiting this function ctx->rem < SHA256_BLOCK_BYTE_LEN

  assert((ctx != NULL) && (data != NULL));

  if(byte_len == 0) {
    return;
  }

  // Accumulate the overall size
  ctx->len += byte_len;

  // Less than a block. Store the data in a temporary buffer
  if((ctx->rem != 0) && ((ctx->rem + byte_len) < SHA256_BLOCK_BYTE_LEN)) {
    my_memcpy(&ctx->data[ctx->rem], data, byte_len);
    ctx->rem += byte_len;
    return;
  }

  // Complete and compress a previously stored block
  if(ctx->rem != 0) {
    const size_t clen = SHA256_BLOCK_BYTE_LEN - ctx->rem;
    my_memcpy(&ctx->data[ctx->rem], data, clen);
    sha256_compress(ctx, ctx->data, 1);

    data += clen;
    byte_len -= clen;

    ctx->rem = 0;
    secure_clean(ctx->data, SHA256_BLOCK_BYTE_LEN);
  }

  // Compress full blocks
  if(byte_len >= SHA256_BLOCK_BYTE_LEN) {
    const size_t blocks_num           = (byte_len >> 6);
    const size_t full_blocks_byte_len = (blocks_num << 6);

    sha256_compress(ctx, data, blocks_num);

    data += full_blocks_byte_len;
    byte_len -= full_blocks_byte_len;
  }

  // Store the reminder
  my_memcpy(ctx->data, data, byte_len);
  ctx->rem = byte_len;
}

_INLINE_ void sha256_final(OUT uint8_t *dgst, IN OUT sha256_ctx_t *ctx)
{
  assert((ctx != NULL) && (dgst != NULL));
  assert(ctx->rem < SHA256_BLOCK_BYTE_LEN);

  // Byteswap the length in bits of the hashed message
  const uint64_t bswap_len      = bswap_64(8 * ctx->len);
  const size_t   last_block_num = (ctx->rem < 56) ? 1 : 2;
  const size_t   last_qw_pos =
    (last_block_num * SHA256_BLOCK_BYTE_LEN) - sizeof(bswap_len);

  ctx->data[ctx->rem++] = SHA256_MSG_END_SYMBOL;

  // Reset the rest of the data buffer
  my_memset(&ctx->data[ctx->rem], 0, sizeof(ctx->data) - ctx->rem);
  my_memcpy(&ctx->data[last_qw_pos], (const uint8_t *)&bswap_len,
            sizeof(bswap_len));

  // Compress the final block
  sha256_compress(ctx, ctx->data, last_block_num);

  // This implementation assumes running on a Little endian machine
  ctx->state.w[0] = bswap_32(ctx->state.w[0]);
  ctx->state.w[1] = bswap_32(ctx->state.w[1]);
  ctx->state.w[2] = bswap_32(ctx->state.w[2]);
  ctx->state.w[3] = bswap_32(ctx->state.w[3]);
  ctx->state.w[4] = bswap_32(ctx->state.w[4]);
  ctx->state.w[5] = bswap_32(ctx->state.w[5]);
  ctx->state.w[6] = bswap_32(ctx->state.w[6]);
  ctx->state.w[7] = bswap_32(ctx->state.w[7]);
  my_memcpy(dgst, &ctx->state, SHA256_HASH_BYTE_LEN);

  secure_clean(ctx, sizeof(*ctx));
}

void sha256(OUT uint8_t *dgst,
            IN const uint8_t *  data,
            IN const size_t     byte_len,
            IN const sha_impl_t impl)
{
  assert((data != NULL) || (dgst != NULL));

  sha256_ctx_t ctx = {0};
  ctx.impl         = impl;
  sha256_init(&ctx);
  sha256_update(&ctx, data, byte_len);
  sha256_final(dgst, &ctx);
}
