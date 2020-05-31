// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "internal/defs.h"

typedef enum sha_impl_e
{
  GENERIC_IMPL,

#if defined(X86_64)
  AVX_IMPL,
  OPENSSL_AVX_IMPL,
#endif

#if defined(AVX2_SUPPORT)
  AVX2_IMPL,
  OPENSSL_AVX2_IMPL,
#endif

#if defined(AVX512_SUPPORT)
  AVX512_IMPL,
#endif

#if defined(X86_64_SHA_SUPPORT)
  SHA_EXT_IMPL,
  OPENSSL_SHA_EXT_IMPL,
#endif

#if defined(NEON_SUPPORT)
  NEON_IMPL,
  OPENSSL_NEON_IMPL,
#endif

#if defined(AARCH64_SHA_SUPPORT)
  SHA_EXT_IMPL,
  OPENSSL_SHA_EXT_IMPL,
#endif

} sha_impl_t;

#define SHA256_HASH_BYTE_LEN 32
#define SHA512_HASH_BYTE_LEN 64

void sha256(OUT uint8_t *dgst,
            IN const uint8_t *data,
            IN size_t         byte_len,
            IN sha_impl_t     impl);

void sha512(OUT uint8_t *dgst,
            IN const uint8_t *data,
            IN size_t         byte_len,
            IN sha_impl_t     impl);
