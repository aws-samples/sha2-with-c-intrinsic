// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <immintrin.h>

typedef __m512i vec_t;

#define ADD64(a, b)             (_mm512_add_epi64(a, b))
#define ADD32(a, b)             (_mm512_add_epi32(a, b))
#define ALIGNR8(a, b, mask)     (_mm512_alignr_epi8(a, b, mask))
#define LOAD(mem)               (_mm512_loadu_si512((const vec_t *)(mem)))
#define MADD32(src, imm8, a, b) (_mm512_mask_add_epi32(src, imm8, a, b))
#define ROR32(a, imm8)          (_mm512_ror_epi32(a, imm8))
#define ROR64(a, imm8)          (_mm512_ror_epi64(a, imm8))
#define SHUF32(a, mask)         (_mm512_shuffle_epi32(a, mask))
#define SHUF8(a, mask)          (_mm512_shuffle_epi8(a, mask))
#define SLL32(a, imm8)          (_mm512_slli_epi32(a, imm8))
#define SLL64(a, imm8)          (_mm512_slli_epi64(a, imm8))
#define SRL32(a, imm8)          (_mm512_srli_epi32(a, imm8))
#define SRL64(a, imm8)          (_mm512_srli_epi64(a, imm8))
#define STORE(mem, reg)         (_mm512_store_si512((vec_t *)(mem), reg))

#define LOAD128(mem)       (_mm_loadu_si128((const __m128i *)(mem)))
#define STORE128(mem, reg) (_mm_store_si128((__m128i *)(mem), reg))

#define STOREU4(mem3, mem2, mem1, mem0, reg)           \
  do {                                                 \
    STORE128(mem0, _mm512_extracti32x4_epi32(reg, 0)); \
    STORE128(mem1, _mm512_extracti32x4_epi32(reg, 1)); \
    STORE128(mem2, _mm512_extracti32x4_epi32(reg, 2)); \
    STORE128(mem3, _mm512_extracti32x4_epi32(reg, 3)); \
  } while(0)

#define LOADU4(mem3, mem2, mem1, mem0, reg)            \
  do {                                                 \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem0), 0); \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem1), 1); \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem2), 2); \
    (reg) = _mm512_inserti32x4(reg, LOAD128(mem3), 3); \
  } while(0)

// In every 128-bit value choose the two lowest 32-bit values.
#define LOW32X2_MASK (0x3333)
// In every 128-bit value choose the two highest 32-bit values.
#define HIGH32X2_MASK (0xcccc)
