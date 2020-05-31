// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// An implementation of the compress function of SHA256 using avx/avx2/avx512
// It was translated from assembly (OpenSSL) to C by
//
// Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

// This file depends on vec_t and on the following macros:
// LOAD, ADD32, ALIGNR8, SRL32, SLL32, SRL64

#define SHA256_WORD_BIT_LEN (8 * sizeof(sha256_word_t))

_INLINE_ void rotate_x(vec_t x[4])
{
  const vec_t tmp = x[0];
  x[0]            = x[1];
  x[1]            = x[2];
  x[2]            = x[3];
  x[3]            = tmp;
}

#ifndef ALTERNATIVE_AVX512_IMPL

_INLINE_ vec_t sha256_update_x_avx(vec_t                x[4],
                                   const sha256_word_t *k256_p,
                                   const vec_t          lo_mask,
                                   const vec_t          hi_mask)
{
  vec_t t[4];

  // This function recieves 4 128-bit registers x[3:0]=d[15:0] and calculates:
  // s0 = sigma0(d[(i + 1) % 16])
  // s1 = sigma1(d[(i + 14) % 16])
  // d[i % 16] += s0 + s1 + d[(i + 9) % 16]
  //
  // For x[0]=d[3:0]
  //
  // This means that
  // res[0] depends on d[1] (for s0) d[14] (for s1) and d[9]
  // res[1] depends on d[2] (for s0) d[15] (for s1) and d[10]
  // res[2] depends on d[3] (for s0) res[0] (for s1) and d[11]
  // res[3] depends on d[4] (for s0) res[1] (for s1) and d[12]

  t[0] = ALIGNR8(x[1], x[0], 4); // d[4:1]
  t[3] = ALIGNR8(x[3], x[2], 4); // d[12:9]
  t[2] = SRL32(t[0], sigma0_0);  // d[4:1] >> s0[0]
  x[0] = ADD32(x[0], t[3]);      // d[3:0] + d[12:9]

  t[3] = SRL32(t[0], sigma0_2);                       // d[4:1] >> s0[2]
  t[1] = SLL32(t[0], SHA256_WORD_BIT_LEN - sigma0_1); // d[4:1] << (32 - s0[1])
  t[0] = t[3] ^ t[2];                                 // (d[4:1] >> s0[2]) ^
                                                      //   (d[4:1] >> s0[0])
  t[3] = SHUF32(x[3], 0xfa);                          // d[15,15,14,14]
  t[2] = SRL32(t[2], sigma0_1 - sigma0_0);            // d[4:1] >> s0[1]
  t[0] ^= t[1] ^ t[2];                                // ROTR(d[4:1], s0[1]) ^
                                                      //   (d[4:1] >> s0[2]) ^
                                                      //   (d[4:1] >> s0[0])
  t[1] = SLL32(t[1], sigma0_1 - sigma0_0);            // d[4:1] << (32 - s0[0])
  t[2] = SRL32(t[3], sigma1_2);                       // d[15,15,14,14] >> s1[2]
  t[3] = SRL64(t[3], sigma1_0);                       // ROTR(d[-,15,-,14], s1[0])
  x[0] = ADD32(x[0], t[0] ^ t[1]);                    // d[3:0] + sigma0(d[4:1])

  t[2] ^= t[3]; // d[15,15,14,14] >> s1[2] ^ ROTR(d[-,15,-,14], s1[0])
  t[3] = SRL64(t[3], sigma1_1 - sigma1_0); // ROTR(d[-,15,-,14], s1[1])
  t[2] = SHUF8(t[2] ^ t[3], lo_mask);      // sigma1(d[Zero,Zero,15,14])
  x[0] = ADD32(x[0], t[2]);                // d[3:0] + sigma0(d[4:1]) +
                                           // sigma1(d[-,-,15,14]) + d[12:9]

  // When calculating s1 = sigma1(s1) for the upper dwords
  // we use the already updated d[1:0]
  t[3] = SHUF32(x[0], 0x50);               // d[1,1,0,0]
  t[2] = SRL32(t[3], sigma1_2);            // d[1,1,0,0] >> s1[2]
  t[3] = SRL64(t[3], sigma1_0);            // ROTR(d[-,1,-,0]) >> s1[0]
  t[2] ^= t[3];                            // ROTR(d[-,1,-,0]) >> s1[0] ^
                                           //   d[1,1,0,0] >> s1[2]
  t[3] = SRL64(t[3], sigma1_1 - sigma1_0); // ROTR(d[-,1,-,0]) >> s1[1]

  // sigma1(d[0,x[1],0,x[0]])
  // sigma1(d[x[1],x[0],Zero,Zero])
  x[0] = ADD32(x[0], SHUF8(t[2] ^ t[3], hi_mask));

  rotate_x(x);

  return ADD32(x[3], LOAD(k256_p));
}

#else

_INLINE_ vec_t sha256_update_x_avx(vec_t                x[4],
                                   const sha256_word_t *k256_p,
                                   UNUSED const vec_t   lo_mask,
                                   UNUSED const vec_t   hi_mask)
{
  vec_t t[2];
  vec_t s0;
  vec_t s1;

  // This function recieves 4 128-bit registers x[3:0]=d[15:0] and calculates:
  // s0 = sigma0(d[(i + 1) % 16])
  // s1 = sigma1(d[(i + 14) % 16])
  // d[i % 16] += s0 + s1 + d[(i + 9) % 16]
  //
  // For x[0]=d[3:0]
  //
  // This means that
  // res[0] depends on d[1] (for s0) d[14] (for s1) and d[9]
  // res[1] depends on d[2] (for s0) d[15] (for s1) and d[10]
  // res[2] depends on d[3] (for s0) res[0] (for s1) and d[11]
  // res[3] depends on d[4] (for s0) res[1] (for s1) and d[12]

  t[0] = ALIGNR8(x[1], x[0], 4); // d[4:1]
  t[1] = ALIGNR8(x[3], x[2], 4); // d[12:9]
  x[0] = ADD32(x[0], t[1]);      // d[3:0] + d[12:9]
  s0   = ROR32(t[0], sigma0_0) ^ ROR32(t[0], sigma0_1) ^ SRL32(t[0], sigma0_2);
  x[0] = ADD32(x[0], s0); // d[3:0] + d[12:9] + sigma0(d[4:1])

  t[1] = SHUF32(x[3], 0xfe); // d[-,-,15,14]
  s1   = ROR32(t[1], sigma1_0) ^ ROR32(t[1], sigma1_1) ^ SRL32(t[1], sigma1_2);
  x[0] = MADD32(x[0], LOW32X2_MASK, x[0], s1);

  t[1] = SHUF32(x[0], 0x40);
  s1   = ROR32(t[1], sigma1_0) ^ ROR32(t[1], sigma1_1) ^ SRL32(t[1], sigma1_2);
  x[0] = MADD32(x[0], HIGH32X2_MASK, x[0], s1);

  rotate_x(x);

  return ADD32(x[3], LOAD(k256_p));
}

#endif
