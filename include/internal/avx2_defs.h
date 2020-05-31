// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <immintrin.h>

typedef __m256i vec_t;

#define ADD32(a, b)             (_mm256_add_epi32(a, b))
#define ADD64(a, b)             (_mm256_add_epi64(a, b))
#define ALIGNR8(a, b, mask)     (_mm256_alignr_epi8(a, b, mask))
#define LOAD(mem)               (_mm256_loadu_si256((const __m256i *)(mem)))
#define MADD32(src, imm8, a, b) (_mm256_mask_add_epi32(src, imm8, a, b))
#define ROR32(a, imm8)          (_mm256_ror_epi32(a, imm8))
#define ROR64(a, imm8)          (_mm256_ror_epi64(a, imm8))
#define SHUF8(a, mask)          (_mm256_shuffle_epi8(a, mask))
#define SHUF32(a, mask)         (_mm256_shuffle_epi32(a, mask))
#define SLL32(a, imm8)          (_mm256_slli_epi32(a, imm8))
#define SLL64(a, imm8)          (_mm256_slli_epi64(a, imm8))
#define SRL32(a, imm8)          (_mm256_srli_epi32(a, imm8))
#define SRL64(a, imm8)          (_mm256_srli_epi64(a, imm8))
#define STORE(mem, reg)         (_mm256_store_si256((__m256i *)(mem), reg))

#define LOAD128(mem)       (_mm_loadu_si128((const __m128i *)(mem)))
#define STORE128(mem, reg) (_mm_store_si128((__m128i *)(mem), reg))

// The _mm256_storeu2_m128i and _mm256_loadu2_m128i APIs are defined in Clang but
// not in GCC
#if defined(__clang__)
#  define STOREU2(hi_mem, lo_mem, reg) \
    (_mm256_storeu2_m128i((__m128i *)(hi_mem), (__m128i *)(lo_mem), reg))

#  define LOADU2(hi_mem, lo_mem, reg)                       \
    ((reg) = _mm256_loadu2_m128i((const __m128i *)(hi_mem), \
                                 (const __m128i *)(lo_mem)))

#else
#  define STOREU2(hi_mem, lo_mem, reg)                    \
    do {                                                  \
      STORE128(lo_mem, _mm256_extracti128_si256(reg, 0)); \
      STORE128(hi_mem, _mm256_extracti128_si256(reg, 1)); \
    } while(0)

#  define LOADU2(hi_mem, lo_mem, reg)                          \
    do {                                                       \
      reg = _mm256_insertf128_si256(reg, LOAD128(hi_mem), 1);  \
      reg = _mm256_insertf128_si256(x[i], LOAD128(lo_mem), 0); \
    } while(0)
#endif

// In every 128-bit value choose the two lowest 32-bit values.
#define LOW32X2_MASK (0x33)
// In every 128-bit value choose the two highest 32-bit values.
#define HIGH32X2_MASK (0xcc)
