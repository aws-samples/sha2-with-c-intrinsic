// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#define SUCCESS 0
#define FAILURE (-1)
#define GUARD(x)         \
  do {                   \
    if(SUCCESS != (x)) { \
      return FAILURE;    \
    }                    \
  } while(0)

/////////////////////////////
//  X86_64 specific options
/////////////////////////////

#if defined(X86_64)
#  define RUN_X86_64(x) \
    do {                \
      x                 \
    } while(0)
#else
#  define RUN_X86_64(x)
#endif

#if defined(AVX2_SUPPORT)
#  define RUN_AVX2(x) \
    do {              \
      x               \
    } while(0)
#else
#  define RUN_AVX2(x)
#endif

#if defined(AVX512_SUPPORT)
#  define RUN_AVX512(x) \
    do {                \
      x                 \
    } while(0)
#else
#  define RUN_AVX512(x)
#endif

#if defined(X86_64_SHA_SUPPORT)
#  define RUN_X86_64_SHA_EXT(x) \
    do {                        \
      x                         \
    } while(0)
#else
#  define RUN_X86_64_SHA_EXT(x)
#endif

/////////////////////////////
//  AARCH64 specific options
/////////////////////////////

#if defined(NEON_SUPPORT)
#  define RUN_NEON(x) \
    do {              \
      x               \
    } while(0)
#else
#  define RUN_NEON(x)
#endif

#if defined(AARCH64_SHA_SUPPORT)
#  define RUN_AARCH64_SHA_EXT(x) \
    do {                         \
      x                          \
    } while(0)
#else
#  define RUN_AARCH64_SHA_EXT(x)
#endif
    
/////////////////////////////
//  Inline utilities
/////////////////////////////

void print(const uint8_t *a, const int byte_len)
{
  for(int i = byte_len - 1; i >= 0; i--) {
    printf("%.2x", a[i]);
  }
  printf("\n\n");
}

_INLINE_ void rand_data(OUT uint8_t *out, IN const size_t byte_len)
{
  for(size_t i = 0; i < byte_len; i++) {
    out[i] = rand();
  }
}
