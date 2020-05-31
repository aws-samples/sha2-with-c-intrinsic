// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <immintrin.h>

typedef __m128i vec_t;

#define ADD32(a, b)             (_mm_add_epi32(a, b))
#define ADD64(a, b)             (_mm_add_epi64(a, b))
#define ALIGNR8(a, b, mask)     (_mm_alignr_epi8(a, b, mask))
#define BLEND16(a, b, mask)     (_mm_blend_epi16(a, b, mask))
#define LOAD(mem)               (_mm_loadu_si128((const __m128i *)(mem)))
#define MADD32(src, imm8, a, b) (_mm_mask_add_epi32(src, imm8, a, b))
#define ROR32(a, imm8)          (_mm_ror_epi32(a, imm8))
#define ROR64(a, imm8)          (_mm_ror_epi64(a, imm8))
#define SETR32(e0, e1, e2, e3)  (_mm_setr_epi32(e0, e1, e2, e3))
#define SET64(e1, e0)           (_mm_set_epi64x(e1, e0))
#define SHUF8(a, mask)          (_mm_shuffle_epi8(a, mask))
#define SHUF32(a, mask)         (_mm_shuffle_epi32(a, mask))
#define SLL32(a, imm8)          (_mm_slli_epi32(a, imm8))
#define SLL64(a, imm8)          (_mm_slli_epi64(a, imm8))
#define SRL32(a, imm8)          (_mm_srli_epi32(a, imm8))
#define SRL64(a, imm8)          (_mm_srli_epi64(a, imm8))
#define STORE(mem, reg)         (_mm_store_si128((__m128i *)(mem), reg))

#define LOW32X2_MASK  (0x3)
#define HIGH32X2_MASK (0xc)
