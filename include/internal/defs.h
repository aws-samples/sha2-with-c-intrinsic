// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IN
#define OUT

#define _INLINE_ static inline
#define ALIGN(n) __attribute__((aligned(n)))

#if defined(__GNUC__) || defined(__clang__)
#  define UNUSED __attribute__((unused))
#else
#  define UNUSED
#endif

#define LSB1(x) ((x)&0x1)
#define LSB2(x) ((x)&0x3)
#define LSB4(x) ((x)&0xf)

#define ROTR16(x, s) (((x) >> (s)) | (x) << (16 - (s)))
#define ROTR32(x, s) (((x) >> (s)) | (x) << (32 - (s)))
#define ROTR64(x, s) (((x) >> (s)) | (x) << (64 - (s)))

#if defined(__GNUC__) && __GNUC__ >= 2
_INLINE_ uint64_t bswap_64(uint64_t x) { return __builtin_bswap64(x); }
_INLINE_ uint64_t bswap_32(uint64_t x) { return __builtin_bswap32(x); }
#else
_INLINE_ uint32_t bswap_32(uint32_t x)
{
  x = ROTR16(x, 16);
  x = ((x & UINT32_C(0xff00ff00)) >> 8) | ((x & UINT32_C(0x00ff00ff)) << 8);
  return x;
}

_INLINE_ uint64_t bswap_64(uint64_t x)
{
  return bswap_32(x >> 32) | (((uint64_t)bswap_32(x)) << 32);
}
#endif

#if defined(__GNUC__) && (__GNUC__ >= 8)
#  define GCC_SUPPORT_UNROLL_PRAGMA
#endif

// A better macro should have the form
// #define PRAGMA_LOOP_UNROLL(x)  _Pragma("GCC unroll x")
// But apparantly this is hard to achieve with different compilers
#if defined(DONT_USE_UNROLL_PRAGMA)
#  define PRAGMA_LOOP_UNROLL_2
#  define PRAGMA_LOOP_UNROLL_4
#  define PRAGMA_LOOP_UNROLL_8
#  define PRAGMA_LOOP_UNROLL_12
#  define PRAGMA_LOOP_UNROLL_16
#  define PRAGMA_LOOP_UNROLL_48
#  define PRAGMA_LOOP_UNROLL_64
#  define PRAGMA_LOOP_UNROLL_80
#else
#  if defined(GCC_SUPPORT_UNROLL_PRAGMA)
#    define PRAGMA_LOOP_UNROLL_2  _Pragma("GCC unroll 2")
#    define PRAGMA_LOOP_UNROLL_4  _Pragma("GCC unroll 4")
#    define PRAGMA_LOOP_UNROLL_8  _Pragma("GCC unroll 8")
#    define PRAGMA_LOOP_UNROLL_12 _Pragma("GCC unroll 12")
#    define PRAGMA_LOOP_UNROLL_16 _Pragma("GCC unroll 16")
#    define PRAGMA_LOOP_UNROLL_48 _Pragma("GCC unroll 48")
#    define PRAGMA_LOOP_UNROLL_64 _Pragma("GCC unroll 64")
#    define PRAGMA_LOOP_UNROLL_80 _Pragma("GCC unroll 80")
#  elif defined(__clang__)
#    define PRAGMA_LOOP_UNROLL_2  _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_4  _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_8  _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_12 _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_16 _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_48 _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_64 _Pragma("unroll")
#    define PRAGMA_LOOP_UNROLL_80 _Pragma("unroll")
#  else
#    define PRAGMA_LOOP_UNROLL_2
#    define PRAGMA_LOOP_UNROLL_4
#    define PRAGMA_LOOP_UNROLL_8
#    define PRAGMA_LOOP_UNROLL_12
#    define PRAGMA_LOOP_UNROLL_16
#    define PRAGMA_LOOP_UNROLL_48
#    define PRAGMA_LOOP_UNROLL_64
#    define PRAGMA_LOOP_UNROLL_80
#  endif
#endif

//////////////////////////
//  Helper functions
///////////////////////////

// my_memcpy avoids the undefined behaviour of memcpy when byte_len=0
_INLINE_ void *my_memcpy(void *dst, const void *src, size_t byte_len)
{
  if(byte_len == 0) {
    return dst;
  }

  return memcpy(dst, src, byte_len);
}

// my_memset avoids the undefined behaviour of memset when byte_len=0
_INLINE_ void *my_memset(void *dst, const int ch, size_t byte_len)
{
  if(byte_len == 0) {
    return dst;
  }

  return memset(dst, ch, byte_len);
}

_INLINE_ void secure_clean(OUT void *p, IN const size_t byte_len)
{
  typedef void *(*memset_t)(void *, int, size_t);
  static volatile memset_t memset_func = my_memset;
  memset_func(p, 0, byte_len);
}

///////////////////////////////////////////
//  Controlling the OpenSSL borrowed code
///////////////////////////////////////////

#if defined(X86_64)
// In OpenSSL the OPENSSL_ia32cap_P array holds the return values (in
// RAX,RBX,RCX,RDX registesrs) of executing the Intel CPUID leaf 7 instruction.
// The assembly code chooses the relevant SHA implementation according to this
// array.

extern unsigned int OPENSSL_ia32cap_P_local[4];

#  define CLEAR_OPENSSL_CAP_ARRAY     \
    do {                              \
      OPENSSL_ia32cap_P_local[0] = 0; \
      OPENSSL_ia32cap_P_local[1] = 0; \
      OPENSSL_ia32cap_P_local[2] = 0; \
      OPENSSL_ia32cap_P_local[3] = 0; \
    } while(0)

// RAX[30] - Intel CPU bit
// RBX[9]  - SSSE3 bit
// RBX[28] - AVX bit
#  define RUN_OPENSSL_CODE_WITH_AVX(x)                      \
    do {                                                    \
      OPENSSL_ia32cap_P_local[0] |= (1 << 30);              \
      OPENSSL_ia32cap_P_local[1] |= ((1 << 9) | (1 << 28)); \
      {x} CLEAR_OPENSSL_CAP_ARRAY;                          \
    } while(0)

// RCX[3] - BMI1 bit
// RCX[5] - AVX2 bit
// RCX[8] - BMI2 bit
#  define RUN_OPENSSL_CODE_WITH_AVX2(x)                               \
    do {                                                              \
      OPENSSL_ia32cap_P_local[2] |= ((1 << 8) | (1 << 5) | (1 << 3)); \
      {x} CLEAR_OPENSSL_CAP_ARRAY;                                    \
    } while(0)

// RCX[29] - SHA_NI (EXT) bit
#  define RUN_OPENSSL_CODE_WITH_SHA_EXT(x)     \
    do {                                       \
      OPENSSL_ia32cap_P_local[2] |= (1 << 29); \
      {x} CLEAR_OPENSSL_CAP_ARRAY;             \
    } while(0)

#endif

#if defined(AARCH64)

extern unsigned int OPENSSL_armcap_P_local;

#  define CLEAR_OPENSSL_CAP_ARRAY \
    do {                          \
      OPENSSL_armcap_P_local = 0; \
    } while(0)

#  define ARMV7_NEON   (1 << 0)
#  define ARMV8_SHA256 (1 << 4)
#  define ARMV8_SHA512 (1 << 6)

#  define RUN_OPENSSL_CODE_WITH_NEON(x)     \
    do {                                    \
      OPENSSL_armcap_P_local |= ARMV7_NEON; \
      {x} CLEAR_OPENSSL_CAP_ARRAY;          \
    } while(0)

#  define RUN_OPENSSL_CODE_WITH_SHA256_EXT(x) \
    do {                                      \
      OPENSSL_armcap_P_local |= ARMV8_SHA256; \
      {x} CLEAR_OPENSSL_CAP_ARRAY;            \
    } while(0)

#  define RUN_OPENSSL_CODE_WITH_SHA512_EXT(x) \
    do {                                      \
      OPENSSL_armcap_P_local |= ARMV8_SHA512; \
      {x} CLEAR_OPENSSL_CAP_ARRAY;            \
    } while(0)
#endif
